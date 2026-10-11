# Security model

What SomeDesk protects, how, and what the server can still see.

* **Login:** OPAQUE (RFC 9807). The server never receives the password or anything that allows
  an offline dictionary attack without its OPRF key. Usernames are bound into the transcript.
* **Identity key:** each user has an Ed25519 identity key. It is stored on the server only as an
  XChaCha20-Poly1305 blob under a key derived (HKDF) from OPAQUE's export key — i.e. from the
  password. A server compromise does not reveal it.
* **Devices:** every device has its own X25519 key, certified by the user's identity key.
  Devices come online with a bearer token (stored hashed on the server); the identity private key
  is not kept on disk.
* **Sessions:** `Noise_XX_25519_ChaChaPoly_BLAKE2s` between the two devices, bound to the session
  id, with certificates exchanged inside the encrypted handshake. Each side checks the peer's
  certificate chain itself. The relay forwards ciphertext only (verified by tests that tap it).
* **Interception check:** both sides display identity fingerprints. Each client also remembers
  the identity key of everyone it has connected with (trust on first use, like SSH) and warns
  loudly if it changes, which is what a malicious server would have to do to get in between.
  The viewer stops before connecting; the host's prompt turns into a warning.
* **Who may connect:** the host accepts every connection unless it comes from one of its own
  account's devices with “unattended access” on, or from a device the user ticked “let this device
  connect without asking” for. That permission is tied to the device key *and* the user's identity
  key, and can be revoked under Contacts.
* **Clipboard:** text is shared inside the encrypted session in both directions (switchable in
  the app). The host's clipboard is only sent after someone copies something during the
  session, never what it held before.
* **File transfer:** files travel inside the encrypted session. The receiver writes to a hidden
  partial file and only keeps it if size and SHA-256 match; names are sanitized so a peer cannot
  write outside `~/Downloads/SomeDesk`. The host saves files from the viewer directly (the viewer
  controls it anyway); the viewer is asked before accepting each file from the host.
* **Direct connections:** when both devices allow it, they exchange candidate addresses through
  the server and connect straight to each other over QUIC (hole punching through NATs, with
  low-TTL punch packets so stray first packets don't spoil the NAT mapping). Whichever path the
  viewer's first Noise message arrives on wins; if nothing direct works within 2.5 s, the relay is
  used. The QUIC layer of a direct connection uses throwaway certificates; authenticity comes from
  the Noise handshake as always. Turning direct connections off keeps a device's IP addresses from
  being shared with peers.
* **What the server does see:** who connects to whom, when, and how much data flows.
* **Recovery key:** a second copy of the identity key is sealed under a 160-bit recovery key that
  is shown once at sign-up (`XXXX-XXXX-…`, with a checksum that catches typos). To reset a
  forgotten password, the client proves it holds the recovery key by signing a server challenge
  with a key derived from it, opens the recovery copy and re-seals it under the new password.
  The server can't open either copy or reset a password without the key. Recovery keys are
  single-use: a reset issues a new one. Without the password *and* the recovery key, the identity
  is lost by design.
