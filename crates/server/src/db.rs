//! Database access. All queries are plain parameterized SQL.

use rand::Rng;
use somedesk_crypto::opaque::ServerSetup;
use somedesk_proto::control::{DeviceCert, EncryptedKeyBundle, RecoverySetup};
use somedesk_proto::{DEVICE_ID_MAX, DEVICE_ID_MIN};
use sqlx::{PgPool, Row};

pub async fn migrate(pool: &PgPool) -> anyhow::Result<()> {
    sqlx::migrate!("./migrations").run(pool).await?;
    Ok(())
}

/// Loads the OPAQUE server setup, creating it on first start.
pub async fn load_or_create_opaque_setup(pool: &PgPool) -> anyhow::Result<ServerSetup> {
    let fresh = ServerSetup::generate();
    sqlx::query("INSERT INTO server_config (key, value) VALUES ('opaque_setup', $1) ON CONFLICT (key) DO NOTHING")
        .bind(fresh.to_bytes())
        .execute(pool)
        .await?;
    let bytes: Vec<u8> =
        sqlx::query_scalar("SELECT value FROM server_config WHERE key = 'opaque_setup'").fetch_one(pool).await?;
    Ok(ServerSetup::from_bytes(&bytes)?)
}

pub struct UserRow {
    pub id: i64,
    pub username: String,
    pub password_file: Vec<u8>,
    pub identity_pk: [u8; 32],
    pub key_bundle: EncryptedKeyBundle,
    pub recovery: Option<RecoverySetup>,
}

pub async fn get_user(pool: &PgPool, username: &str) -> anyhow::Result<Option<UserRow>> {
    let row = sqlx::query(
        "SELECT id, username, password_file, identity_pk, key_bundle, recovery_pk, recovery_bundle
         FROM users WHERE username = $1",
    )
    .bind(username)
    .fetch_optional(pool)
    .await?;
    row.map(|r| {
        let pk: Vec<u8> = r.get("identity_pk");
        let bundle: Vec<u8> = r.get("key_bundle");
        let recovery_pk: Option<Vec<u8>> = r.get("recovery_pk");
        let recovery_bundle: Option<Vec<u8>> = r.get("recovery_bundle");
        let recovery = match (recovery_pk, recovery_bundle) {
            (Some(pk), Some(bundle)) => Some(RecoverySetup {
                recovery_pk: pk.try_into().map_err(|_| anyhow::anyhow!("corrupt recovery_pk"))?,
                key_bundle: postcard::from_bytes(&bundle)?,
            }),
            _ => None,
        };
        Ok(UserRow {
            id: r.get("id"),
            username: r.get("username"),
            password_file: r.get("password_file"),
            identity_pk: pk.try_into().map_err(|_| anyhow::anyhow!("corrupt identity_pk"))?,
            key_bundle: postcard::from_bytes(&bundle)?,
            recovery,
        })
    })
    .transpose()
}

/// Returns `None` if the username is taken.
pub async fn create_user(
    pool: &PgPool,
    username: &str,
    password_file: &[u8],
    identity_pk: &[u8; 32],
    bundle: &EncryptedKeyBundle,
    recovery: &RecoverySetup,
) -> anyhow::Result<Option<i64>> {
    Ok(sqlx::query_scalar(
        "INSERT INTO users (username, password_file, identity_pk, key_bundle, recovery_pk, recovery_bundle)
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (username) DO NOTHING RETURNING id",
    )
    .bind(username)
    .bind(password_file)
    .bind(identity_pk.as_slice())
    .bind(postcard::to_stdvec(bundle)?)
    .bind(recovery.recovery_pk.as_slice())
    .bind(postcard::to_stdvec(&recovery.key_bundle)?)
    .fetch_optional(pool)
    .await?)
}

pub async fn set_recovery(pool: &PgPool, user_id: i64, recovery: &RecoverySetup) -> anyhow::Result<()> {
    sqlx::query("UPDATE users SET recovery_pk = $2, recovery_bundle = $3 WHERE id = $1")
        .bind(user_id)
        .bind(recovery.recovery_pk.as_slice())
        .bind(postcard::to_stdvec(&recovery.key_bundle)?)
        .execute(pool)
        .await?;
    Ok(())
}

/// Replaces the password (OPAQUE record and password-sealed bundle) and the recovery key in one
/// step, so a reset never leaves the account half-updated.
pub async fn reset_password(
    pool: &PgPool,
    user_id: i64,
    password_file: &[u8],
    bundle: &EncryptedKeyBundle,
    recovery: &RecoverySetup,
) -> anyhow::Result<()> {
    sqlx::query(
        "UPDATE users SET password_file = $2, key_bundle = $3, recovery_pk = $4, recovery_bundle = $5 WHERE id = $1",
    )
    .bind(user_id)
    .bind(password_file)
    .bind(postcard::to_stdvec(bundle)?)
    .bind(recovery.recovery_pk.as_slice())
    .bind(postcard::to_stdvec(&recovery.key_bundle)?)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn user_exists(pool: &PgPool, username: &str) -> anyhow::Result<bool> {
    Ok(sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM users WHERE username = $1)")
        .bind(username)
        .fetch_one(pool)
        .await?)
}

#[derive(Clone)]
pub struct DeviceRow {
    pub id: u64,
    pub user_id: i64,
    pub username: String,
    pub name: String,
    pub cert: DeviceCert,
    pub token_hash: Vec<u8>,
}

fn device_from_row(r: sqlx::postgres::PgRow) -> anyhow::Result<DeviceRow> {
    let cert: Vec<u8> = r.get("cert");
    let id: i64 = r.get("id");
    Ok(DeviceRow {
        id: id as u64,
        user_id: r.get("user_id"),
        username: r.get("username"),
        name: r.get("name"),
        cert: postcard::from_bytes(&cert)?,
        token_hash: r.get("token_hash"),
    })
}

const DEVICE_COLUMNS: &str =
    "d.id, d.user_id, u.username, d.name, d.cert, d.token_hash FROM devices d JOIN users u ON u.id = d.user_id";

/// Inserts a device under a fresh random 9-digit id.
pub async fn insert_device(pool: &PgPool, user_id: i64, cert: &DeviceCert, token_hash: &[u8]) -> anyhow::Result<u64> {
    let cert_bytes = postcard::to_stdvec(cert)?;
    for _ in 0..20 {
        let id = rand::thread_rng().gen_range(DEVICE_ID_MIN..=DEVICE_ID_MAX);
        let inserted = sqlx::query(
            "INSERT INTO devices (id, user_id, name, device_pk, cert, token_hash) VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(id as i64)
        .bind(user_id)
        .bind(&cert.device_name)
        .bind(cert.device_pk.as_slice())
        .bind(&cert_bytes)
        .bind(token_hash)
        .execute(pool)
        .await?
        .rows_affected();
        if inserted == 1 {
            return Ok(id);
        }
    }
    anyhow::bail!("could not allocate a device id")
}

pub async fn get_device(pool: &PgPool, device_id: u64) -> anyhow::Result<Option<DeviceRow>> {
    sqlx::query(&format!("SELECT {DEVICE_COLUMNS} WHERE d.id = $1"))
        .bind(device_id as i64)
        .fetch_optional(pool)
        .await?
        .map(device_from_row)
        .transpose()
}

pub async fn list_devices(pool: &PgPool, user_id: i64) -> anyhow::Result<Vec<DeviceRow>> {
    sqlx::query(&format!("SELECT {DEVICE_COLUMNS} WHERE d.user_id = $1 ORDER BY d.created_at"))
        .bind(user_id)
        .fetch_all(pool)
        .await?
        .into_iter()
        .map(device_from_row)
        .collect()
}

pub async fn delete_device(pool: &PgPool, user_id: i64, device_id: u64) -> anyhow::Result<bool> {
    Ok(sqlx::query("DELETE FROM devices WHERE id = $1 AND user_id = $2")
        .bind(device_id as i64)
        .bind(user_id)
        .execute(pool)
        .await?
        .rows_affected()
        == 1)
}

pub async fn touch_device(pool: &PgPool, device_id: u64) -> anyhow::Result<()> {
    sqlx::query("UPDATE devices SET last_seen = now() WHERE id = $1").bind(device_id as i64).execute(pool).await?;
    Ok(())
}

pub async fn audit(pool: &PgPool, user_id: Option<i64>, device_id: Option<u64>, event: &str, detail: Option<&str>) {
    let res = sqlx::query("INSERT INTO audit_log (user_id, device_id, event, detail) VALUES ($1, $2, $3, $4)")
        .bind(user_id)
        .bind(device_id.map(|d| d as i64))
        .bind(event)
        .bind(detail)
        .execute(pool)
        .await;
    if let Err(e) = res {
        tracing::warn!("audit log write failed: {e}");
    }
}
