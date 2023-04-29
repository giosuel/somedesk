//! Database access. All queries are plain parameterized SQL.

use rand::Rng;
use somedesk_crypto::opaque::ServerSetup;
use somedesk_proto::control::{DeviceCert, EncryptedKeyBundle, RecoverySetup};
use somedesk_proto::org::{OrgDeviceCert, SignedPolicy};
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
    /// The authenticator app's secret, when two-factor authentication is on.
    pub totp_secret: Option<Vec<u8>>,
    pub totp_last_step: Option<i64>,
}

pub async fn get_user(pool: &PgPool, username: &str) -> anyhow::Result<Option<UserRow>> {
    let row = sqlx::query(
        "SELECT id, username, password_file, identity_pk, key_bundle, recovery_pk, recovery_bundle,
                totp_secret, totp_last_step
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
            totp_secret: r.get("totp_secret"),
            totp_last_step: r.get("totp_last_step"),
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
    pub device_pk: [u8; 32],
    pub name: String,
    /// The account the device is signed in to, with its certificate for the device key.
    pub account: Option<DeviceAccount>,
    /// The organisation that enrolled the device, with the service worker's certificate.
    pub org: Option<(u64, OrgDeviceCert)>,
}

#[derive(Clone)]
pub struct DeviceAccount {
    pub user_id: i64,
    pub username: String,
    pub cert: DeviceCert,
}

fn device_from_row(r: sqlx::postgres::PgRow) -> anyhow::Result<DeviceRow> {
    let id: i64 = r.get("id");
    let device_pk: Vec<u8> = r.get("device_pk");
    let user_id: Option<i64> = r.get("user_id");
    let username: Option<String> = r.get("username");
    let cert: Option<Vec<u8>> = r.get("cert");
    let org_id: Option<i64> = r.get("org_id");
    let org_cert: Option<Vec<u8>> = r.get("org_cert");
    let org = match (org_id, org_cert) {
        (Some(id), Some(cert)) => Some((id as u64, postcard::from_bytes(&cert)?)),
        _ => None,
    };
    let account = match (user_id, username, cert) {
        (Some(user_id), Some(username), Some(cert)) => {
            Some(DeviceAccount { user_id, username, cert: postcard::from_bytes(&cert)? })
        }
        _ => None,
    };
    Ok(DeviceRow {
        id: id as u64,
        device_pk: device_pk.try_into().map_err(|_| anyhow::anyhow!("corrupt device_pk"))?,
        name: r.get("name"),
        account,
        org,
    })
}

const DEVICE_COLUMNS: &str = "d.id, d.device_pk, d.name, d.user_id, u.username, d.cert, d.org_id, d.org_cert
     FROM devices d LEFT JOIN users u ON u.id = d.user_id";

/// Registers a device key under a fresh random 9-digit id.
pub async fn insert_device(pool: &PgPool, device_pk: &[u8; 32], name: &str) -> anyhow::Result<u64> {
    for _ in 0..20 {
        let id = rand::thread_rng().gen_range(DEVICE_ID_MIN..=DEVICE_ID_MAX);
        let inserted =
            sqlx::query("INSERT INTO devices (id, name, device_pk) VALUES ($1, $2, $3) ON CONFLICT (id) DO NOTHING")
                .bind(id as i64)
                .bind(name)
                .bind(device_pk.as_slice())
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

pub async fn get_device_by_key(pool: &PgPool, device_pk: &[u8; 32]) -> anyhow::Result<Option<DeviceRow>> {
    sqlx::query(&format!("SELECT {DEVICE_COLUMNS} WHERE d.device_pk = $1"))
        .bind(device_pk.as_slice())
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

pub async fn set_device_name(pool: &PgPool, device_id: u64, name: &str) -> anyhow::Result<()> {
    sqlx::query("UPDATE devices SET name = $2 WHERE id = $1").bind(device_id as i64).bind(name).execute(pool).await?;
    Ok(())
}

/// Signs a device in to an account.
pub async fn attach_device(pool: &PgPool, device_id: u64, user_id: i64, cert: &DeviceCert) -> anyhow::Result<()> {
    sqlx::query("UPDATE devices SET user_id = $2, cert = $3, name = $4 WHERE id = $1")
        .bind(device_id as i64)
        .bind(user_id)
        .bind(postcard::to_stdvec(cert)?)
        .bind(&cert.device_name)
        .execute(pool)
        .await?;
    Ok(())
}

/// Signs a device out of its account (only if it is on `user_id`'s, when given).
pub async fn detach_device(pool: &PgPool, device_id: u64, user_id: Option<i64>) -> anyhow::Result<bool> {
    Ok(sqlx::query(
        "UPDATE devices SET user_id = NULL, cert = NULL
         WHERE id = $1 AND user_id IS NOT NULL AND ($2::BIGINT IS NULL OR user_id = $2)",
    )
    .bind(device_id as i64)
    .bind(user_id)
    .execute(pool)
    .await?
    .rows_affected()
        == 1)
}

/// Enrolls a device into an organisation.
pub async fn set_device_org(pool: &PgPool, device_id: u64, cert: &OrgDeviceCert) -> anyhow::Result<()> {
    sqlx::query("UPDATE devices SET org_id = $2, org_cert = $3, name = $4 WHERE id = $1")
        .bind(device_id as i64)
        .bind(cert.org_id as i64)
        .bind(postcard::to_stdvec(cert)?)
        .bind(&cert.device_name)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn list_org_devices(pool: &PgPool, org_id: u64) -> anyhow::Result<Vec<DeviceRow>> {
    sqlx::query(&format!("SELECT {DEVICE_COLUMNS} WHERE d.org_id = $1 ORDER BY d.created_at"))
        .bind(org_id as i64)
        .fetch_all(pool)
        .await?
        .into_iter()
        .map(device_from_row)
        .collect()
}

// ---------------------------------------------------------------- vault

/// The account's vault: (version, blob), or (0, empty) if it has none yet.
pub async fn get_vault(pool: &PgPool, user_id: i64) -> anyhow::Result<(u64, Vec<u8>)> {
    let row =
        sqlx::query("SELECT version, blob FROM vaults WHERE user_id = $1").bind(user_id).fetch_optional(pool).await?;
    Ok(row.map(|r| (r.get::<i64, _>("version") as u64, r.get("blob"))).unwrap_or_default())
}

/// Replaces the vault if it is still at `base_version`; returns the new version, or `None` if
/// another device changed it in the meantime.
pub async fn put_vault(pool: &PgPool, user_id: i64, base_version: u64, blob: &[u8]) -> anyhow::Result<Option<u64>> {
    let new = base_version as i64 + 1;
    let rows = if base_version == 0 {
        sqlx::query("INSERT INTO vaults (user_id, version, blob) VALUES ($1, 1, $2) ON CONFLICT (user_id) DO NOTHING")
            .bind(user_id)
            .bind(blob)
            .execute(pool)
            .await?
    } else {
        sqlx::query("UPDATE vaults SET version = $3, blob = $4, updated_at = now() WHERE user_id = $1 AND version = $2")
            .bind(user_id)
            .bind(base_version as i64)
            .bind(new)
            .bind(blob)
            .execute(pool)
            .await?
    };
    Ok((rows.rows_affected() == 1).then_some(new as u64))
}

// ---------------------------------------------------------------- two-factor authentication

pub async fn set_totp(
    pool: &PgPool,
    user_id: i64,
    secret: Option<&[u8]>,
    last_step: Option<u64>,
) -> anyhow::Result<()> {
    sqlx::query("UPDATE users SET totp_secret = $2, totp_last_step = $3 WHERE id = $1")
        .bind(user_id)
        .bind(secret)
        .bind(last_step.map(|s| s as i64))
        .execute(pool)
        .await?;
    Ok(())
}

/// Records the step of a used code, unless a later one was used meanwhile.
pub async fn use_totp_step(pool: &PgPool, user_id: i64, step: u64) -> anyhow::Result<bool> {
    Ok(sqlx::query(
        "UPDATE users SET totp_last_step = $2 WHERE id = $1 AND (totp_last_step IS NULL OR totp_last_step < $2)",
    )
    .bind(user_id)
    .bind(step as i64)
    .execute(pool)
    .await?
    .rows_affected()
        == 1)
}

pub async fn get_user_by_id(pool: &PgPool, user_id: i64) -> anyhow::Result<Option<UserRow>> {
    let username: Option<String> =
        sqlx::query_scalar("SELECT username FROM users WHERE id = $1").bind(user_id).fetch_optional(pool).await?;
    match username {
        Some(u) => get_user(pool, &u).await,
        None => Ok(None),
    }
}

// ---------------------------------------------------------------- organisations

pub struct OrgRow {
    pub id: u64,
    pub name: String,
    pub org_pk: [u8; 32],
    pub created_by: Option<i64>,
    pub policy: Option<SignedPolicy>,
}

fn org_from_row(r: sqlx::postgres::PgRow) -> anyhow::Result<OrgRow> {
    let id: i64 = r.get("id");
    let pk: Vec<u8> = r.get("org_pk");
    let policy: Option<Vec<u8>> = r.get("policy");
    let signature: Option<Vec<u8>> = r.get("signature");
    Ok(OrgRow {
        id: id as u64,
        name: r.get("name"),
        org_pk: pk.try_into().map_err(|_| anyhow::anyhow!("corrupt org_pk"))?,
        created_by: r.get("created_by"),
        policy: policy.zip(signature).map(|(policy, signature)| SignedPolicy { policy, signature }),
    })
}

const ORG_COLUMNS: &str =
    "o.id, o.name, o.org_pk, o.created_by, p.policy, p.signature FROM orgs o LEFT JOIN org_policies p ON p.org_id = o.id";

pub async fn create_org(
    pool: &PgPool,
    name: &str,
    org_pk: &[u8; 32],
    user_id: i64,
    sealed_key: &[u8],
) -> anyhow::Result<u64> {
    let mut tx = pool.begin().await?;
    for _ in 0..20 {
        let id = rand::thread_rng().gen_range(DEVICE_ID_MIN..=DEVICE_ID_MAX);
        let inserted = sqlx::query(
            "INSERT INTO orgs (id, name, org_pk, created_by) VALUES ($1, $2, $3, $4) ON CONFLICT (id) DO NOTHING",
        )
        .bind(id as i64)
        .bind(name)
        .bind(org_pk.as_slice())
        .bind(user_id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if inserted == 1 {
            sqlx::query("INSERT INTO org_keys (org_id, user_id, sealed_key) VALUES ($1, $2, $3)")
                .bind(id as i64)
                .bind(user_id)
                .bind(sealed_key)
                .execute(&mut *tx)
                .await?;
            tx.commit().await?;
            return Ok(id);
        }
    }
    anyhow::bail!("could not allocate an organisation id")
}

pub async fn get_org(pool: &PgPool, org_id: u64) -> anyhow::Result<Option<OrgRow>> {
    sqlx::query(&format!("SELECT {ORG_COLUMNS} WHERE o.id = $1"))
        .bind(org_id as i64)
        .fetch_optional(pool)
        .await?
        .map(org_from_row)
        .transpose()
}

pub async fn list_orgs(pool: &PgPool) -> anyhow::Result<Vec<OrgRow>> {
    sqlx::query(&format!("SELECT {ORG_COLUMNS} ORDER BY o.created_at"))
        .fetch_all(pool)
        .await?
        .into_iter()
        .map(org_from_row)
        .collect()
}

/// Stores `policy` (version `version`) if it is newer than the current one.
pub async fn put_org_policy(pool: &PgPool, org_id: u64, version: u64, policy: &SignedPolicy) -> anyhow::Result<bool> {
    Ok(sqlx::query(
        "INSERT INTO org_policies (org_id, version, policy, signature) VALUES ($1, $2, $3, $4)
         ON CONFLICT (org_id) DO UPDATE SET version = $2, policy = $3, signature = $4, updated_at = now()
         WHERE org_policies.version < $2",
    )
    .bind(org_id as i64)
    .bind(version as i64)
    .bind(&policy.policy)
    .bind(&policy.signature)
    .execute(pool)
    .await?
    .rows_affected()
        == 1)
}

pub async fn get_org_key(pool: &PgPool, org_id: u64, user_id: i64) -> anyhow::Result<Option<Vec<u8>>> {
    Ok(sqlx::query_scalar("SELECT sealed_key FROM org_keys WHERE org_id = $1 AND user_id = $2")
        .bind(org_id as i64)
        .bind(user_id)
        .fetch_optional(pool)
        .await?)
}

pub async fn put_org_key(pool: &PgPool, org_id: u64, user_id: i64, sealed_key: &[u8]) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO org_keys (org_id, user_id, sealed_key) VALUES ($1, $2, $3)
         ON CONFLICT (org_id, user_id) DO UPDATE SET sealed_key = $3",
    )
    .bind(org_id as i64)
    .bind(user_id)
    .bind(sealed_key)
    .execute(pool)
    .await?;
    Ok(())
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
