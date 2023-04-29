//! Unattended access with a password set up on the host itself.
//!
//! The host plays the OPAQUE server for its own password: it keeps a password file (no
//! password, and nothing to guess it from offline) and its own OPAQUE keys; the viewer plays the
//! client. The run happens inside the Noise channel and is bound to it twice:
//!
//! * the host is named by its device key in the transcript, and
//! * the Noise handshake hash is the OPAQUE context.
//!
//! So a run can't be relayed to another host or another channel, and someone posing as the host
//! learns nothing they could use to guess the password offline. The authenticator code is
//! checked separately by the host (see [`crate::totp`]).

use crate::opaque::{identifiers_for, ServerSetup, Suite};
use crate::CryptoError;
use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration, ClientRegistrationFinishParameters,
    CredentialFinalization, CredentialRequest, CredentialResponse, ServerLogin, ServerLoginStartParameters,
    ServerRegistration,
};
use rand::rngs::OsRng;

/// The client name in every unattended-access transcript.
const CLIENT: &str = "somedesk unattended access";

/// What the host stores for its unattended-access password.
pub struct HostRecord {
    pub setup: Vec<u8>,
    pub password_file: Vec<u8>,
}

/// Sets the host's password: runs both sides of an OPAQUE registration locally.
pub fn create_record(host_pk: &[u8; 32], password: &str) -> Result<HostRecord, CryptoError> {
    let setup = ServerSetup::generate();
    let ids = identifiers_for(CLIENT, host_pk);
    let start =
        ClientRegistration::<Suite>::start(&mut OsRng, password.as_bytes()).map_err(|_| CryptoError::Malformed)?;
    let response = ServerRegistration::<Suite>::start(&setup.0, start.message, CLIENT.as_bytes())
        .map_err(|_| CryptoError::Malformed)?;
    let finish = start
        .state
        .finish(&mut OsRng, password.as_bytes(), response.message, ClientRegistrationFinishParameters::new(ids, None))
        .map_err(|_| CryptoError::Malformed)?;
    let file = ServerRegistration::<Suite>::finish(finish.message);
    Ok(HostRecord { setup: setup.to_bytes(), password_file: file.serialize().to_vec() })
}

pub struct ViewerState(ClientLogin<Suite>);

/// Viewer, step 1: the request for the host.
pub fn viewer_start(password: &str) -> Result<(Vec<u8>, ViewerState), CryptoError> {
    let r = ClientLogin::<Suite>::start(&mut OsRng, password.as_bytes()).map_err(|_| CryptoError::Malformed)?;
    Ok((r.message.serialize().to_vec(), ViewerState(r.state)))
}

/// Viewer, step 2: the finalization for the host. Fails with [`CryptoError::AuthFailed`] on a
/// wrong password, or a host that isn't `host_pk` or isn't at the other end of this channel.
pub fn viewer_finish(
    st: ViewerState,
    password: &str,
    host_pk: &[u8; 32],
    handshake_hash: &[u8; 32],
    response: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let resp = CredentialResponse::<Suite>::deserialize(response).map_err(|_| CryptoError::Malformed)?;
    let params = ClientLoginFinishParameters::new(Some(handshake_hash), identifiers_for(CLIENT, host_pk), None);
    let r = st.0.finish(password.as_bytes(), resp, params).map_err(|_| CryptoError::AuthFailed)?;
    Ok(r.message.serialize().to_vec())
}

pub struct HostState(ServerLogin<Suite>);

/// Host, step 1: answers the viewer's request.
pub fn host_start(
    record: &HostRecord,
    host_pk: &[u8; 32],
    handshake_hash: &[u8; 32],
    request: &[u8],
) -> Result<(Vec<u8>, HostState), CryptoError> {
    let setup = ServerSetup::from_bytes(&record.setup)?;
    let file = ServerRegistration::<Suite>::deserialize(&record.password_file).map_err(|_| CryptoError::Malformed)?;
    let req = CredentialRequest::<Suite>::deserialize(request).map_err(|_| CryptoError::Malformed)?;
    let params =
        ServerLoginStartParameters { context: Some(handshake_hash), identifiers: identifiers_for(CLIENT, host_pk) };
    let r = ServerLogin::start(&mut OsRng, &setup.0, Some(file), req, CLIENT.as_bytes(), params)
        .map_err(|_| CryptoError::Malformed)?;
    Ok((r.message.serialize().to_vec(), HostState(r.state)))
}

/// Host, step 2: succeeds only if the viewer knows the password.
pub fn host_finish(st: HostState, finalization: &[u8]) -> Result<(), CryptoError> {
    let fin = CredentialFinalization::<Suite>::deserialize(finalization).map_err(|_| CryptoError::Malformed)?;
    st.0.finish(fin).map(|_| ()).map_err(|_| CryptoError::AuthFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOST: [u8; 32] = [7; 32];
    const CHANNEL: [u8; 32] = [9; 32];

    fn run(record: &HostRecord, password: &str, host_pk: &[u8; 32], viewer_hash: &[u8; 32]) -> Result<(), CryptoError> {
        let (m1, vst) = viewer_start(password)?;
        let (m2, hst) = host_start(record, &HOST, &CHANNEL, &m1)?;
        let m3 = viewer_finish(vst, password, host_pk, viewer_hash, &m2)?;
        host_finish(hst, &m3)
    }

    #[test]
    fn the_right_password_on_the_right_channel() {
        let record = create_record(&HOST, "unattended pw").unwrap();
        run(&record, "unattended pw", &HOST, &CHANNEL).unwrap();
        assert!(matches!(run(&record, "wrong", &HOST, &CHANNEL), Err(CryptoError::AuthFailed)));
        // Relayed from another channel (a man in the middle has a different handshake hash).
        assert!(run(&record, "unattended pw", &HOST, &[1; 32]).is_err());
        // Or towards another host.
        assert!(run(&record, "unattended pw", &[8; 32], &CHANNEL).is_err());
    }

    #[test]
    fn the_record_holds_no_password() {
        let record = create_record(&HOST, "my-unattended-password").unwrap();
        assert!(!record.password_file.windows(22).any(|w| w == b"my-unattended-password"));
    }
}
