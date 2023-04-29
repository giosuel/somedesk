//! OPAQUE (RFC 9807) password authentication.
//!
//! Besides authenticating the user, a successful run gives the client an `export_key` that only
//! someone who knows the password can derive. We use it to encrypt the user's identity key, so
//! the server stores a key bundle it cannot open.

use crate::CryptoError;
use opaque_ke::{
    key_exchange::tripledh::TripleDh, ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialFinalization, CredentialRequest, CredentialResponse, Identifiers,
    RegistrationRequest, RegistrationResponse, RegistrationUpload, Ristretto255, ServerLogin,
    ServerLoginStartParameters, ServerRegistration,
};
use rand::rngs::OsRng;
use zeroize::Zeroizing;

pub struct Suite;

impl opaque_ke::CipherSuite for Suite {
    type OprfCs = Ristretto255;
    type KeGroup = Ristretto255;
    type KeyExchange = TripleDh;
    type Ksf = argon2::Argon2<'static>;
}

/// Server identifier mixed into every OPAQUE transcript.
const SERVER_IDENTITY: &[u8] = b"somedesk";

fn identifiers(username: &str) -> Identifiers<'_> {
    identifiers_for(username, SERVER_IDENTITY)
}

/// The client and server names mixed into a transcript. Unattended access names the host
/// differently from the server, so a run against one can't stand in for the other.
pub(crate) fn identifiers_for<'a>(client: &'a str, server: &'a [u8]) -> Identifiers<'a> {
    Identifiers { client: Some(client.as_bytes()), server: Some(server) }
}

/// Key that only a holder of the password can derive (64 bytes).
pub type ExportKey = Zeroizing<Vec<u8>>;

/// Long-term OPAQUE server keys. Must be persisted; losing it invalidates all passwords.
pub struct ServerSetup(pub(crate) opaque_ke::ServerSetup<Suite>);

impl ServerSetup {
    pub fn generate() -> Self {
        Self(opaque_ke::ServerSetup::<Suite>::new(&mut OsRng))
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.serialize().to_vec()
    }
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        opaque_ke::ServerSetup::<Suite>::deserialize(bytes).map(Self).map_err(|_| CryptoError::Malformed)
    }
}

// ---------------------------------------------------------------- client side

pub struct ClientRegistrationState {
    pub(crate) state: ClientRegistration<Suite>,
    pub(crate) username: String,
}

/// Registration step 1. Returns the message for the server.
pub fn client_register_start(
    username: &str,
    password: &str,
) -> Result<(Vec<u8>, ClientRegistrationState), CryptoError> {
    let r = ClientRegistration::<Suite>::start(&mut OsRng, password.as_bytes()).map_err(|_| CryptoError::Malformed)?;
    Ok((r.message.serialize().to_vec(), ClientRegistrationState { state: r.state, username: username.to_owned() }))
}

/// Registration step 2. Returns the upload for the server and the export key.
pub fn client_register_finish(
    st: ClientRegistrationState,
    password: &str,
    server_response: &[u8],
) -> Result<(Vec<u8>, ExportKey), CryptoError> {
    let resp = RegistrationResponse::<Suite>::deserialize(server_response).map_err(|_| CryptoError::Malformed)?;
    let r = st
        .state
        .finish(
            &mut OsRng,
            password.as_bytes(),
            resp,
            ClientRegistrationFinishParameters::new(identifiers(&st.username), None),
        )
        .map_err(|_| CryptoError::Malformed)?;
    Ok((r.message.serialize().to_vec(), Zeroizing::new(r.export_key.to_vec())))
}

pub struct ClientLoginState {
    pub(crate) state: ClientLogin<Suite>,
    pub(crate) username: String,
}

/// Login step 1.
pub fn client_login_start(username: &str, password: &str) -> Result<(Vec<u8>, ClientLoginState), CryptoError> {
    let r = ClientLogin::<Suite>::start(&mut OsRng, password.as_bytes()).map_err(|_| CryptoError::Malformed)?;
    Ok((r.message.serialize().to_vec(), ClientLoginState { state: r.state, username: username.to_owned() }))
}

/// Login step 2. Fails with [`CryptoError::AuthFailed`] on a wrong password (or a server that
/// does not hold this user's password file). Returns the finalization message and export key.
pub fn client_login_finish(
    st: ClientLoginState,
    password: &str,
    server_response: &[u8],
) -> Result<(Vec<u8>, ExportKey), CryptoError> {
    let resp = CredentialResponse::<Suite>::deserialize(server_response).map_err(|_| CryptoError::Malformed)?;
    let r = st
        .state
        .finish(password.as_bytes(), resp, ClientLoginFinishParameters::new(None, identifiers(&st.username), None))
        .map_err(|_| CryptoError::AuthFailed)?;
    Ok((r.message.serialize().to_vec(), Zeroizing::new(r.export_key.to_vec())))
}

// ---------------------------------------------------------------- server side

/// Registration step 1 on the server.
pub fn server_register_start(setup: &ServerSetup, username: &str, request: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let req = RegistrationRequest::<Suite>::deserialize(request).map_err(|_| CryptoError::Malformed)?;
    let r =
        ServerRegistration::<Suite>::start(&setup.0, req, username.as_bytes()).map_err(|_| CryptoError::Malformed)?;
    Ok(r.message.serialize().to_vec())
}

/// Registration step 2 on the server. Returns the password file to store.
pub fn server_register_finish(upload: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let up = RegistrationUpload::<Suite>::deserialize(upload).map_err(|_| CryptoError::Malformed)?;
    Ok(ServerRegistration::<Suite>::finish(up).serialize().to_vec())
}

pub struct ServerLoginState(pub(crate) ServerLogin<Suite>);

/// Login step 1 on the server. Pass `None` for an unknown user: the protocol then continues
/// with a fake record so the response does not reveal whether the account exists.
pub fn server_login_start(
    setup: &ServerSetup,
    password_file: Option<&[u8]>,
    username: &str,
    request: &[u8],
) -> Result<(Vec<u8>, ServerLoginState), CryptoError> {
    let file =
        password_file.map(ServerRegistration::<Suite>::deserialize).transpose().map_err(|_| CryptoError::Malformed)?;
    let req = CredentialRequest::<Suite>::deserialize(request).map_err(|_| CryptoError::Malformed)?;
    let r = ServerLogin::start(
        &mut OsRng,
        &setup.0,
        file,
        req,
        username.as_bytes(),
        ServerLoginStartParameters { context: None, identifiers: identifiers(username) },
    )
    .map_err(|_| CryptoError::Malformed)?;
    Ok((r.message.serialize().to_vec(), ServerLoginState(r.state)))
}

/// Login step 2 on the server. Succeeds only if the client proved knowledge of the password.
pub fn server_login_finish(st: ServerLoginState, finalization: &[u8]) -> Result<(), CryptoError> {
    let fin = CredentialFinalization::<Suite>::deserialize(finalization).map_err(|_| CryptoError::Malformed)?;
    st.0.finish(fin).map(|_| ()).map_err(|_| CryptoError::AuthFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn register(setup: &ServerSetup, user: &str, pw: &str) -> (Vec<u8>, ExportKey) {
        let (m1, st) = client_register_start(user, pw).unwrap();
        let m2 = server_register_start(setup, user, &m1).unwrap();
        let (m3, export) = client_register_finish(st, pw, &m2).unwrap();
        (server_register_finish(&m3).unwrap(), export)
    }

    fn login(setup: &ServerSetup, file: Option<&[u8]>, user: &str, pw: &str) -> Result<ExportKey, CryptoError> {
        let (m1, cst) = client_login_start(user, pw)?;
        let (m2, sst) = server_login_start(setup, file, user, &m1)?;
        let (m3, export) = client_login_finish(cst, pw, &m2)?;
        server_login_finish(sst, &m3)?;
        Ok(export)
    }

    #[test]
    fn register_then_login_yields_same_export_key() {
        let setup = ServerSetup::generate();
        let (file, reg_export) = register(&setup, "alice", "correct horse");
        let login_export = login(&setup, Some(&file), "alice", "correct horse").unwrap();
        assert_eq!(*reg_export, *login_export);
        assert_eq!(reg_export.len(), 64);
    }

    #[test]
    fn wrong_password_fails() {
        let setup = ServerSetup::generate();
        let (file, _) = register(&setup, "alice", "correct horse");
        assert!(matches!(login(&setup, Some(&file), "alice", "wrong"), Err(CryptoError::AuthFailed)));
    }

    #[test]
    fn unknown_user_fails_like_wrong_password() {
        let setup = ServerSetup::generate();
        assert!(matches!(login(&setup, None, "nobody", "pw"), Err(CryptoError::AuthFailed)));
    }

    #[test]
    fn password_file_is_bound_to_username() {
        let setup = ServerSetup::generate();
        let (file, _) = register(&setup, "alice", "pw");
        // A malicious server presenting alice's record for "mallory" must not let the login succeed.
        assert!(login(&setup, Some(&file), "mallory", "pw").is_err());
    }

    #[test]
    fn server_setup_survives_serialization() {
        let setup = ServerSetup::generate();
        let (file, _) = register(&setup, "alice", "pw");
        let restored = ServerSetup::from_bytes(&setup.to_bytes()).unwrap();
        login(&restored, Some(&file), "alice", "pw").unwrap();
    }

    #[test]
    fn password_file_does_not_contain_password() {
        let setup = ServerSetup::generate();
        let pw = "super-secret-password-123";
        let (file, _) = register(&setup, "alice", pw);
        assert!(!file.windows(pw.len()).any(|w| w == pw.as_bytes()));
    }
}
