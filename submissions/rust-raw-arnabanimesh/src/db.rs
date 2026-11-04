//! Postgres layer: connection setup, prepared statements and row -> JSON writers.
//!
//! Design notes
//! ------------
//! * Every connection runs with `plan_cache_mode = force_generic_plan`, so Postgres never
//!   re-plans a statement. That only works well if the *generic* plan is safe for every
//!   parameter value. With an unknown `LIMIT $n` the planner assumes ~10% of the table comes
//!   out, which makes it want hash joins against `users`/`articles`. All list queries are
//!   therefore written as "page of ids" + `LATERAL ... LIMIT 1` primary-key lookups, which can
//!   only ever be planned as nested loops over indexes.
//! * Each endpoint is one statement (one round trip, one commit) wherever the spec allows.
//! * Parameters are explicitly cast (`$1::bigint`, `$2::text`, ...), so the Rust parameter types
//!   are deterministic.
//! * Rows are read by column index and written straight into the response buffer as JSON.

use std::cell::Cell;

use tokio_postgres::types::{FromSql, Type};
use tokio_postgres::{Client, NoTls, Row, Statement};

use crate::json;

pub type DbResult<T> = Result<T, tokio_postgres::Error>;

/// `timestamptz` as raw microseconds since 2000-01-01 (the binary wire format), so no chrono
/// conversion or `String` is needed to print it.
pub struct PgTs(pub i64);

impl<'a> FromSql<'a> for PgTs {
    fn from_sql(
        _ty: &Type,
        raw: &'a [u8],
    ) -> Result<Self, Box<dyn std::error::Error + Sync + Send>> {
        let arr: [u8; 8] = raw.try_into()?;
        Ok(PgTs(i64::from_be_bytes(arr)))
    }

    fn accepts(ty: &Type) -> bool {
        *ty == Type::TIMESTAMPTZ || *ty == Type::TIMESTAMP
    }
}

// ---------------------------------------------------------------------------------------------
// SQL
// ---------------------------------------------------------------------------------------------

/// `jit` and parallel query only add latency/CPU contention on a shared 8-core box.
const SESSION_SETUP: &str = "SET jit = off; \
     SET plan_cache_mode = force_generic_plan; \
     SET max_parallel_workers_per_gather = 0; \
     SET synchronous_commit = on;";

const SQL_TAGS: &str = r#"SELECT array_agg(name) FROM (SELECT name FROM tags ORDER BY name) t"#;

// ---- users: columns are always (id, username, email, bio, image[, password_hash]) ------------

const SQL_REGISTER: &str = r#"INSERT INTO users (username, email, password_hash)
VALUES ($1::text, $2::text, $3::text)
RETURNING id, username, email, bio, image"#;

const SQL_LOGIN: &str = r#"SELECT id, username, email, bio, image, password_hash
FROM users WHERE email = $1::text"#;

const SQL_GET_USER: &str = r#"SELECT id, username, email, bio, image FROM users WHERE id = $1::bigint"#;

const SQL_UPDATE_USER: &str = r#"UPDATE users SET
    email = COALESCE($2::text, email),
    username = COALESCE($3::text, username),
    password_hash = COALESCE($4::text, password_hash),
    bio = COALESCE($5::text, bio),
    image = COALESCE($6::text, image)
WHERE id = $1::bigint
RETURNING id, username, email, bio, image"#;

// ---- profiles: columns are always (id, username, bio, image, following) ---------------------

const SQL_PROFILE: &str = r#"SELECT u.id, u.username, u.bio, u.image,
       ($1::bigint > 0 AND EXISTS (SELECT 1 FROM follows fo
                                    WHERE fo.follower_id = $1::bigint AND fo.followee_id = u.id)) AS following
FROM users u WHERE u.username = $2::text"#;

const SQL_FOLLOW: &str = r#"WITH target AS (SELECT id, username, bio, image FROM users WHERE username = $2::text),
     ins AS (INSERT INTO follows (follower_id, followee_id)
             SELECT $1::bigint, id FROM target
             ON CONFLICT DO NOTHING
             RETURNING 1)
SELECT id, username, bio, image, true AS following FROM target"#;

const SQL_UNFOLLOW: &str = r#"WITH target AS (SELECT id, username, bio, image FROM users WHERE username = $2::text),
     del AS (DELETE FROM follows
              WHERE follower_id = $1::bigint AND followee_id IN (SELECT id FROM target)
              RETURNING 1)
SELECT id, username, bio, image, false AS following FROM target"#;

// ---- single articles: columns are always ARTICLE_COLS ----------------------------------------
//
// (id, slug, title, description, body, created_at, updated_at, tag_list, favorited,
//  favorites_count, username, bio, image, following)

const ARTICLE_SELECT: &str = r#"SELECT a.id, a.slug, a.title, a.description, a.body, a.created_at, a.updated_at,
       ARRAY(SELECT t.name FROM article_tags atg JOIN tags t ON t.id = atg.tag_id
              WHERE atg.article_id = a.id ORDER BY t.name) AS tag_list,
       ($1::bigint > 0 AND EXISTS (SELECT 1 FROM favorites f
                                    WHERE f.article_id = a.id AND f.user_id = $1::bigint)) AS favorited,
       (SELECT count(*)::int4 FROM favorites f2 WHERE f2.article_id = a.id) AS favorites_count,
       u.username, u.bio, u.image,
       ($1::bigint > 0 AND EXISTS (SELECT 1 FROM follows fo
                                    WHERE fo.follower_id = $1::bigint AND fo.followee_id = a.author_id)) AS following
FROM articles a JOIN users u ON u.id = a.author_id
WHERE {WHERE}"#;

const SQL_UPSERT_TAGS: &str = r#"INSERT INTO tags (name) SELECT DISTINCT unnest($1::text[]) ON CONFLICT (name) DO NOTHING"#;

/// One statement, one commit: insert the article, link its tags, return the full article.
/// The tags were upserted (and committed) by the previous statement, so they are visible here.
const SQL_CREATE_ARTICLE: &str = r#"WITH n AS (SELECT nextval(pg_get_serial_sequence('articles', 'id')) AS id),
     new_art AS (
        INSERT INTO articles (id, slug, author_id, title, description, body)
        SELECT n.id, $2::text || '-' || n.id::text, $1::bigint, $3::text, $4::text, $5::text FROM n
        RETURNING id, slug, title, description, body, created_at, updated_at, author_id
     ),
     ins_at AS (
        INSERT INTO article_tags (article_id, tag_id)
        SELECT (SELECT id FROM new_art), t.id FROM tags t WHERE t.name = ANY($6::text[])
        ON CONFLICT DO NOTHING
        RETURNING article_id
     )
SELECT a.id, a.slug, a.title, a.description, a.body, a.created_at, a.updated_at,
       ARRAY(SELECT t.name FROM tags t WHERE t.name = ANY($6::text[]) ORDER BY t.name) AS tag_list,
       false AS favorited,
       0::int4 AS favorites_count,
       u.username, u.bio, u.image,
       EXISTS (SELECT 1 FROM follows fo
                WHERE fo.follower_id = $1::bigint AND fo.followee_id = a.author_id) AS following
FROM new_art a JOIN users u ON u.id = a.author_id"#;

/// Ownership check + update in one statement. Result: (id, author_id, updated).
/// `$6` is the slugified new title (NULL = keep the slug); the SQL appends `-<id>`.
const SQL_UPDATE_ARTICLE: &str = r#"WITH target AS (SELECT id, author_id FROM articles WHERE slug = $1::text),
     upd AS (
        UPDATE articles SET
            title = COALESCE($3::text, title),
            description = COALESCE($4::text, description),
            body = COALESCE($5::text, body),
            slug = CASE WHEN $6::text IS NULL THEN slug ELSE $6::text || '-' || id::text END,
            updated_at = now()
        WHERE id IN (SELECT id FROM target WHERE author_id = $2::bigint)
        RETURNING id
     )
SELECT t.id, t.author_id, EXISTS (SELECT 1 FROM upd) AS updated FROM target t"#;

/// Ownership check + delete in one statement. Result: (author_id, deleted).
/// Comments, tags links and favorites go away through the schema's ON DELETE CASCADE.
const SQL_DELETE_ARTICLE: &str = r#"WITH target AS (SELECT id, author_id FROM articles WHERE slug = $1::text),
     del AS (DELETE FROM articles
              WHERE id IN (SELECT id FROM target WHERE author_id = $2::bigint)
              RETURNING id)
SELECT t.author_id, EXISTS (SELECT 1 FROM del) AS deleted FROM target t"#;

/// Favorite / unfavorite and return the resulting article in the same statement.
/// The final SELECT cannot see the CTE's own writes, so the count is adjusted by the number of
/// rows the CTE actually inserted / deleted.
const SQL_FAVORITE: &str = r#"WITH target AS (SELECT id FROM articles WHERE slug = $2::text),
     ins AS (INSERT INTO favorites (user_id, article_id)
             SELECT $1::bigint, id FROM target
             ON CONFLICT DO NOTHING
             RETURNING 1)
SELECT a.id, a.slug, a.title, a.description, a.body, a.created_at, a.updated_at,
       ARRAY(SELECT t.name FROM article_tags atg JOIN tags t ON t.id = atg.tag_id
              WHERE atg.article_id = a.id ORDER BY t.name) AS tag_list,
       true AS favorited,
       ((SELECT count(*) FROM favorites f2 WHERE f2.article_id = a.id) + (SELECT count(*) FROM ins))::int4 AS favorites_count,
       u.username, u.bio, u.image,
       EXISTS (SELECT 1 FROM follows fo
                WHERE fo.follower_id = $1::bigint AND fo.followee_id = a.author_id) AS following
FROM articles a JOIN users u ON u.id = a.author_id
WHERE a.id = (SELECT id FROM target)"#;

const SQL_UNFAVORITE: &str = r#"WITH target AS (SELECT id FROM articles WHERE slug = $2::text),
     del AS (DELETE FROM favorites
              WHERE user_id = $1::bigint AND article_id IN (SELECT id FROM target)
              RETURNING 1)
SELECT a.id, a.slug, a.title, a.description, a.body, a.created_at, a.updated_at,
       ARRAY(SELECT t.name FROM article_tags atg JOIN tags t ON t.id = atg.tag_id
              WHERE atg.article_id = a.id ORDER BY t.name) AS tag_list,
       false AS favorited,
       ((SELECT count(*) FROM favorites f2 WHERE f2.article_id = a.id) - (SELECT count(*) FROM del))::int4 AS favorites_count,
       u.username, u.bio, u.image,
       EXISTS (SELECT 1 FROM follows fo
                WHERE fo.follower_id = $1::bigint AND fo.followee_id = a.author_id) AS following
FROM articles a JOIN users u ON u.id = a.author_id
WHERE a.id = (SELECT id FROM target)"#;

// ---- article lists: columns are always LIST_COLS ----------------------------------------------
//
// (cnt, id, slug, title, description, created_at, updated_at, tag_list, favorited,
//  favorites_count, username, bio, image, following)
//
// `cnt` is the capped (1000) total from the reference count statement. It is computed in the same
// statement and LEFT JOINed, so an empty page (offset past the end) still returns the count.

const LIST_TEMPLATE: &str = r#"SELECT tot.cnt, s.id, s.slug, s.title, s.description, s.created_at, s.updated_at,
       s.tag_list, s.favorited, s.favorites_count, s.username, s.bio, s.image, s.following
FROM ({COUNT}) tot
LEFT JOIN LATERAL (
    SELECT ids.id, a.slug, a.title, a.description, a.created_at, a.updated_at,
           ARRAY(SELECT t.name FROM article_tags atg JOIN tags t ON t.id = atg.tag_id
                  WHERE atg.article_id = ids.id ORDER BY t.name) AS tag_list,
           ($1::bigint > 0 AND EXISTS (SELECT 1 FROM favorites f
                                        WHERE f.article_id = ids.id AND f.user_id = $1::bigint)) AS favorited,
           (SELECT count(*)::int4 FROM favorites f2 WHERE f2.article_id = ids.id) AS favorites_count,
           u.username, u.bio, u.image,
           ($1::bigint > 0 AND EXISTS (SELECT 1 FROM follows fo
                                        WHERE fo.follower_id = $1::bigint AND fo.followee_id = a.author_id)) AS following
    FROM ({IDS}) ids
    CROSS JOIN LATERAL (SELECT a0.slug, a0.title, a0.description, a0.created_at, a0.updated_at, a0.author_id
                          FROM articles a0 WHERE a0.id = ids.id LIMIT 1) a
    CROSS JOIN LATERAL (SELECT u0.username, u0.bio, u0.image
                          FROM users u0 WHERE u0.id = a.author_id LIMIT 1) u
) s ON true
ORDER BY s.id DESC"#;

const COUNT_ALL: &str = r#"SELECT count(*)::int8 AS cnt FROM (SELECT 1 FROM articles LIMIT 1000) c"#;
const IDS_ALL: &str = r#"SELECT x.id FROM articles x ORDER BY x.id DESC LIMIT $2::bigint OFFSET $3::bigint"#;

const COUNT_TAG: &str = r#"SELECT count(*)::int8 AS cnt FROM (SELECT 1 FROM article_tags x
    WHERE x.tag_id = (SELECT t.id FROM tags t WHERE t.name = $4::text) LIMIT 1000) c"#;
const IDS_TAG: &str = r#"SELECT x.article_id AS id FROM article_tags x
    WHERE x.tag_id = (SELECT t.id FROM tags t WHERE t.name = $4::text)
    ORDER BY x.article_id DESC LIMIT $2::bigint OFFSET $3::bigint"#;

const COUNT_AUTHOR: &str = r#"SELECT count(*)::int8 AS cnt FROM (SELECT 1 FROM articles x
    WHERE x.author_id = (SELECT au.id FROM users au WHERE au.username = $4::text) LIMIT 1000) c"#;
const IDS_AUTHOR: &str = r#"SELECT x.id FROM articles x
    WHERE x.author_id = (SELECT au.id FROM users au WHERE au.username = $4::text)
    ORDER BY x.id DESC LIMIT $2::bigint OFFSET $3::bigint"#;

const COUNT_FAV: &str = r#"SELECT count(*)::int8 AS cnt FROM (SELECT 1 FROM favorites x
    WHERE x.user_id = (SELECT fu.id FROM users fu WHERE fu.username = $4::text) LIMIT 1000) c"#;
const IDS_FAV: &str = r#"SELECT x.article_id AS id FROM favorites x
    WHERE x.user_id = (SELECT fu.id FROM users fu WHERE fu.username = $4::text)
    ORDER BY x.article_id DESC LIMIT $2::bigint OFFSET $3::bigint"#;

const COUNT_FEED: &str = r#"SELECT count(*)::int8 AS cnt FROM (SELECT 1 FROM articles x
    WHERE x.author_id IN (SELECT ff.followee_id FROM follows ff WHERE ff.follower_id = $1::bigint) LIMIT 1000) c"#;
/// The reference "k-way merge": newest (limit+offset) ids per followee, then the global top page.
const IDS_FEED: &str = r#"SELECT y.id FROM follows fw
    CROSS JOIN LATERAL (SELECT a2.id FROM articles a2
                         WHERE a2.author_id = fw.followee_id
                         ORDER BY a2.id DESC LIMIT ($2::bigint + $3::bigint)) y
    WHERE fw.follower_id = $1::bigint
    ORDER BY y.id DESC LIMIT $2::bigint OFFSET $3::bigint"#;

// ---- comments: columns are always (aid, id, body, created_at, updated_at, username, bio, image,
//      following) ------------------------------------------------------------------------------

/// Article lookup and the (newest 100) comments in one statement. No row = no such article;
/// an article without comments yields one row whose comment columns are NULL.
const SQL_COMMENTS: &str = r#"SELECT a.id AS aid, c.id, c.body, c.created_at, c.updated_at, c.username, c.bio, c.image, c.following
FROM articles a
LEFT JOIN LATERAL (
    SELECT c0.id, c0.body, c0.created_at, c0.updated_at, u.username, u.bio, u.image,
           ($1::bigint > 0 AND EXISTS (SELECT 1 FROM follows fo
                                        WHERE fo.follower_id = $1::bigint AND fo.followee_id = c0.author_id)) AS following
    FROM comments c0
    JOIN users u ON u.id = c0.author_id
    WHERE c0.article_id = a.id
    ORDER BY c0.created_at DESC, c0.id DESC
    LIMIT 100
) c ON true
WHERE a.slug = $2::text
ORDER BY c.created_at DESC, c.id DESC"#;

const SQL_CREATE_COMMENT: &str = r#"WITH art AS (SELECT id FROM articles WHERE slug = $1::text),
     c AS (INSERT INTO comments (article_id, author_id, body)
           SELECT id, $2::bigint, $3::text FROM art
           RETURNING id, article_id, body, created_at, updated_at, author_id)
SELECT c.article_id AS aid, c.id, c.body, c.created_at, c.updated_at, u.username, u.bio, u.image, false AS following
FROM c JOIN users u ON u.id = c.author_id"#;

/// Result: (author_id, deleted). No row = 404, deleted=false = 403.
const SQL_DELETE_COMMENT: &str = r#"WITH target AS (SELECT c.id, c.author_id
                FROM comments c JOIN articles a ON a.id = c.article_id
                WHERE c.id = $1::bigint AND a.slug = $2::text),
     del AS (DELETE FROM comments
              WHERE id IN (SELECT id FROM target WHERE author_id = $3::bigint)
              RETURNING id)
SELECT t.author_id, EXISTS (SELECT 1 FROM del) AS deleted FROM target t"#;

fn article_select(where_clause: &str) -> String {
    ARTICLE_SELECT.replace("{WHERE}", where_clause)
}

fn list_sql(count: &str, ids: &str) -> String {
    LIST_TEMPLATE.replace("{COUNT}", count).replace("{IDS}", ids)
}

// ---------------------------------------------------------------------------------------------
// Connection
// ---------------------------------------------------------------------------------------------

pub struct Stmts {
    pub tags: Statement,
    pub register: Statement,
    pub login: Statement,
    pub get_user: Statement,
    pub update_user: Statement,
    pub profile: Statement,
    pub follow: Statement,
    pub unfollow: Statement,
    pub article_by_slug: Statement,
    pub article_by_id: Statement,
    pub upsert_tags: Statement,
    pub create_article: Statement,
    pub update_article: Statement,
    pub delete_article: Statement,
    pub favorite: Statement,
    pub unfavorite: Statement,
    pub list_all: Statement,
    pub list_tag: Statement,
    pub list_author: Statement,
    pub list_fav: Statement,
    pub list_feed: Statement,
    pub comments: Statement,
    pub create_comment: Statement,
    pub delete_comment: Statement,
}

pub struct PgConn {
    pub client: Client,
    pub s: Stmts,
    /// Requests currently using this connection (single-threaded, so a plain `Cell`).
    pub inflight: Cell<u32>,
}

impl PgConn {
    pub async fn connect_and_prepare(db_url: &str) -> Result<Self, tokio_postgres::Error> {
        let (client, connection) = tokio_postgres::connect(db_url, NoTls).await?;
        tokio::task::spawn_local(async move {
            let _ = connection.await;
        });

        client.batch_execute(SESSION_SETUP).await?;

        let s = Stmts {
            tags: client.prepare(SQL_TAGS).await?,
            register: client.prepare(SQL_REGISTER).await?,
            login: client.prepare(SQL_LOGIN).await?,
            get_user: client.prepare(SQL_GET_USER).await?,
            update_user: client.prepare(SQL_UPDATE_USER).await?,
            profile: client.prepare(SQL_PROFILE).await?,
            follow: client.prepare(SQL_FOLLOW).await?,
            unfollow: client.prepare(SQL_UNFOLLOW).await?,
            article_by_slug: client.prepare(&article_select("a.slug = $2::text")).await?,
            article_by_id: client.prepare(&article_select("a.id = $2::bigint")).await?,
            upsert_tags: client.prepare(SQL_UPSERT_TAGS).await?,
            create_article: client.prepare(SQL_CREATE_ARTICLE).await?,
            update_article: client.prepare(SQL_UPDATE_ARTICLE).await?,
            delete_article: client.prepare(SQL_DELETE_ARTICLE).await?,
            favorite: client.prepare(SQL_FAVORITE).await?,
            unfavorite: client.prepare(SQL_UNFAVORITE).await?,
            list_all: client.prepare(&list_sql(COUNT_ALL, IDS_ALL)).await?,
            list_tag: client.prepare(&list_sql(COUNT_TAG, IDS_TAG)).await?,
            list_author: client.prepare(&list_sql(COUNT_AUTHOR, IDS_AUTHOR)).await?,
            list_fav: client.prepare(&list_sql(COUNT_FAV, IDS_FAV)).await?,
            list_feed: client.prepare(&list_sql(COUNT_FEED, IDS_FEED)).await?,
            comments: client.prepare(SQL_COMMENTS).await?,
            create_comment: client.prepare(SQL_CREATE_COMMENT).await?,
            delete_comment: client.prepare(SQL_DELETE_COMMENT).await?,
        };

        Ok(PgConn {
            client,
            s,
            inflight: Cell::new(0),
        })
    }
}

// ---------------------------------------------------------------------------------------------
// Row -> JSON writers
// ---------------------------------------------------------------------------------------------

fn write_profile_obj(
    out: &mut Vec<u8>,
    username: &str,
    bio: Option<&str>,
    image: Option<&str>,
    following: bool,
) {
    out.extend_from_slice(b"{\"username\":");
    json::put_str(out, username);
    out.extend_from_slice(b",\"bio\":");
    json::put_opt_str(out, bio);
    out.extend_from_slice(b",\"image\":");
    json::put_opt_str(out, image);
    out.extend_from_slice(b",\"following\":");
    json::put_bool(out, following);
    out.push(b'}');
}

/// `{"user": {...}}` from a (id, username, email, bio, image, ..) row.
pub fn write_user(out: &mut Vec<u8>, row: &Row, token: &str) -> DbResult<()> {
    let username: &str = row.try_get(1)?;
    let email: &str = row.try_get(2)?;
    let bio: Option<&str> = row.try_get(3)?;
    let image: Option<&str> = row.try_get(4)?;
    out.extend_from_slice(b"{\"user\":{\"email\":");
    json::put_str(out, email);
    out.extend_from_slice(b",\"token\":");
    json::put_str(out, token);
    out.extend_from_slice(b",\"username\":");
    json::put_str(out, username);
    out.extend_from_slice(b",\"bio\":");
    json::put_opt_str(out, bio);
    out.extend_from_slice(b",\"image\":");
    json::put_opt_str(out, image);
    out.extend_from_slice(b"}}");
    Ok(())
}

/// `{"profile": {...}}` from an (id, username, bio, image, following) row.
pub fn write_profile(out: &mut Vec<u8>, row: &Row) -> DbResult<()> {
    let username: &str = row.try_get(1)?;
    let bio: Option<&str> = row.try_get(2)?;
    let image: Option<&str> = row.try_get(3)?;
    let following: bool = row.try_get(4)?;
    out.extend_from_slice(b"{\"profile\":");
    write_profile_obj(out, username, bio, image, following);
    out.push(b'}');
    Ok(())
}

/// One article object. `off` is the index of the `id` column and `with_body` says whether a
/// `body` column follows `description` (single-article rows: off = 0, body; list rows: off = 1,
/// no body).
pub fn write_article(out: &mut Vec<u8>, row: &Row, off: usize, with_body: bool) -> DbResult<()> {
    let b = if with_body { 1 } else { 0 };
    let slug: &str = row.try_get(off + 1)?;
    let title: &str = row.try_get(off + 2)?;
    let description: &str = row.try_get(off + 3)?;
    let created: PgTs = row.try_get(off + 4 + b)?;
    let updated: PgTs = row.try_get(off + 5 + b)?;
    let tags: Vec<&str> = row.try_get(off + 6 + b)?;
    let favorited: bool = row.try_get(off + 7 + b)?;
    let favorites_count: i32 = row.try_get(off + 8 + b)?;
    let username: &str = row.try_get(off + 9 + b)?;
    let bio: Option<&str> = row.try_get(off + 10 + b)?;
    let image: Option<&str> = row.try_get(off + 11 + b)?;
    let following: bool = row.try_get(off + 12 + b)?;

    out.extend_from_slice(b"{\"slug\":");
    json::put_str(out, slug);
    out.extend_from_slice(b",\"title\":");
    json::put_str(out, title);
    out.extend_from_slice(b",\"description\":");
    json::put_str(out, description);
    if with_body {
        let body: &str = row.try_get(off + 4)?;
        out.extend_from_slice(b",\"body\":");
        json::put_str(out, body);
    }
    out.extend_from_slice(b",\"tagList\":[");
    for (i, t) in tags.iter().enumerate() {
        if i > 0 {
            out.push(b',');
        }
        json::put_str(out, t);
    }
    out.extend_from_slice(b"],\"createdAt\":");
    json::put_pg_ts(out, created.0);
    out.extend_from_slice(b",\"updatedAt\":");
    json::put_pg_ts(out, updated.0);
    out.extend_from_slice(b",\"favorited\":");
    json::put_bool(out, favorited);
    out.extend_from_slice(b",\"favoritesCount\":");
    json::put_i64(out, favorites_count as i64);
    out.extend_from_slice(b",\"author\":");
    write_profile_obj(out, username, bio, image, following);
    out.push(b'}');
    Ok(())
}

/// `{"articles": [...], "articlesCount": n}` from LIST_COLS rows.
pub fn write_article_list(out: &mut Vec<u8>, rows: &[Row]) -> DbResult<()> {
    out.extend_from_slice(b"{\"articles\":[");
    let mut count: i64 = 0;
    let mut first = true;
    for row in rows {
        count = row.try_get(0)?;
        let id: Option<i64> = row.try_get(1)?;
        if id.is_none() {
            continue; // the single NULL row of an empty page
        }
        if !first {
            out.push(b',');
        }
        first = false;
        write_article(out, row, 1, false)?;
    }
    out.extend_from_slice(b"],\"articlesCount\":");
    json::put_i64(out, count);
    out.push(b'}');
    Ok(())
}

/// One comment object from an (aid, id, body, created_at, updated_at, username, bio, image,
/// following) row.
pub fn write_comment(out: &mut Vec<u8>, row: &Row) -> DbResult<()> {
    let id: i64 = row.try_get(1)?;
    let body: &str = row.try_get(2)?;
    let created: PgTs = row.try_get(3)?;
    let updated: PgTs = row.try_get(4)?;
    let username: &str = row.try_get(5)?;
    let bio: Option<&str> = row.try_get(6)?;
    let image: Option<&str> = row.try_get(7)?;
    let following: bool = row.try_get(8)?;

    out.extend_from_slice(b"{\"id\":");
    json::put_i64(out, id);
    out.extend_from_slice(b",\"createdAt\":");
    json::put_pg_ts(out, created.0);
    out.extend_from_slice(b",\"updatedAt\":");
    json::put_pg_ts(out, updated.0);
    out.extend_from_slice(b",\"body\":");
    json::put_str(out, body);
    out.extend_from_slice(b",\"author\":");
    write_profile_obj(out, username, bio, image, following);
    out.push(b'}');
    Ok(())
}

/// `{"comments": [...]}`; skips the NULL row of an article that has no comments.
pub fn write_comments(out: &mut Vec<u8>, rows: &[Row]) -> DbResult<()> {
    out.extend_from_slice(b"{\"comments\":[");
    let mut first = true;
    for row in rows {
        let id: Option<i64> = row.try_get(1)?;
        if id.is_none() {
            continue;
        }
        if !first {
            out.push(b',');
        }
        first = false;
        write_comment(out, row)?;
    }
    out.extend_from_slice(b"]}");
    Ok(())
}

/// `{"tags": [...]}` from the single `array_agg` row.
pub fn write_tags(out: &mut Vec<u8>, row: &Row) -> DbResult<()> {
    let names: Option<Vec<&str>> = row.try_get(0)?;
    out.extend_from_slice(b"{\"tags\":[");
    if let Some(names) = names {
        for (i, n) in names.iter().enumerate() {
            if i > 0 {
                out.push(b',');
            }
            json::put_str(out, n);
        }
    }
    out.extend_from_slice(b"]}");
    Ok(())
}

/// Byte-identical to the SPEC's
/// `trim(both '-' from lower(regexp_replace(x, '[^A-Za-z0-9]+', '-', 'g')))`.
pub fn slugify(title: &str) -> String {
    let mut out = String::with_capacity(title.len());
    let mut prev_dash = true;
    for ch in title.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            prev_dash = false;
        } else if !prev_dash {
            out.push('-');
            prev_dash = true;
        }
    }
    if out.ends_with('-') {
        out.pop();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slugify_matches_spec() {
        assert_eq!(slugify("Hello, World!"), "hello-world");
        assert_eq!(slugify("  --Rust & Postgres--  "), "rust-postgres");
        assert_eq!(slugify("Caf\u{e9} au lait"), "caf-au-lait");
        assert_eq!(slugify("!!!"), "");
        assert_eq!(slugify("A1  B2"), "a1-b2");
    }

    #[test]
    fn templates_have_no_leftover_placeholders() {
        for sql in [
            article_select("a.slug = $2::text"),
            article_select("a.id = $2::bigint"),
            list_sql(COUNT_ALL, IDS_ALL),
            list_sql(COUNT_TAG, IDS_TAG),
            list_sql(COUNT_AUTHOR, IDS_AUTHOR),
            list_sql(COUNT_FAV, IDS_FAV),
            list_sql(COUNT_FEED, IDS_FEED),
        ] {
            assert!(!sql.contains('{') && !sql.contains('}'), "{sql}");
        }
    }
}