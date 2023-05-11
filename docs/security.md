# Security model

What SomeDesk protects, how, and what the server can still see. In short: **every decision
about who gets in is made by the computer being connected to**, with keys the server never
holds. A malicious server can refuse service, but it can't let anyone in.

## Devices

* **Installation ID:** on first start, every installation creates an X25519 device key and
  keeps it on disk. The server assigns a nine-digit ID bound to its public key. To come online,
  the device answers a challenge: the server sends a one-time X25519 key and a nonce, and the
  device proves it holds the private key with an HKDF of the shared secret, bound to both
  public keys (low-order points are rejected). No token is stored anywhere, so a copy of the
  server's database lets nobody come online as a device.
* **Pinning:** each client remembers the device key behind every ID it talks to, and the
  account key if there is one (trust on first use, like SSH). If either changes, the viewer
  stops before connecting and the host's prompt turns into a warning. That's what a malicious
  server would have to do to get in between. Address book entries pin the device key too.
* **Accounts are optional.** A device works by its ID without one. The server lets in devices
  without an account unless it runs with `--accounts-only`, which also makes creating an account
  take an invite code.

## Accounts

* **Login:** OPAQUE (RFC 9807). The server never receives the password or anything that allows
  an offline dictionary attack without its OPRF key. Usernames are bound into the transcript.
* **Identity key:** each account has an Ed25519 identity key. It is stored on the server only as
  an XChaCha20-Poly1305 blob under a key derived (HKDF) from OPAQUE's export key, i.e. from the
  password. A server compromise does not reveal it.
* **Devices of an account:** signing in certifies the device key with the identity key. The
  certificate travels in the session handshake, so the other side checks it itself.
* **Two-factor authentication:** TOTP (RFC 6238, SHA-1, six digits, one step of clock drift
  allowed, each code used once). With it on, signing in on a new device needs a code after the
  password. Turning it off needs a code too, or a sign-in with a code on the same connection in
  the last ten minutes.

## Sessions

* **Channel:** `Noise_XX_25519_ChaChaPoly_BLAKE2s` between the two devices, bound to the session
  id, with the device identities (device key, name, account and organisation certificates)
  exchanged inside the encrypted handshake. The device key is the Noise static key, so the peer
  is authenticated by the handshake itself. The relay forwards ciphertext only (verified by
  tests that tap it).

## Who may connect

The host decides, in one of four ways (see [Ways to connect](connecting.md)). There is no
"always allow".

* **By ID:** the person at the host accepts each connection.
* **Password and code:** the host is an OPAQUE server for its own unattended password
  (identifiers: the host's device key), and the login runs inside the Noise session with the
  handshake hash as context, so a proof can't be relayed into another session. The viewer then
  sends the current TOTP code, checked against the host's own secret. A wrong password still
  gets a finalization message, so timing doesn't tell which part was wrong. After three wrong
  attempts the host is locked for 30 seconds, doubling up to an hour. The server takes no part.
* **Own devices:** off by default; needs the setting on the host and two-factor authentication on
  the account. The host checks that the peer's certificate is signed by its own account's
  identity key, and asks the server whether the device is still on the account, so a removed
  device is shut out at once.
* **Organisation:** see below.

A banner on the host shows every session, however it was let in.

## Address book and saved passwords

* **Vault:** a key derived (HKDF) from the account's identity key encrypts the address book and
  the passwords saved in the account (XChaCha20-Poly1305, the username as associated data). The
  server stores a versioned blob and rejects stale writes, and the clients merge entry by entry.
* **On this device:** passwords saved there go to the system keychain (Secret Service, Windows
  Credential Manager or macOS Keychain). Where none is usable the option isn't offered. TOTP
  codes and secrets are never saved for other devices.

## Organisations

* **Organisation key:** Ed25519. The server stores it only sealed to each admin's identity key
  (X25519 from the Ed25519 key's Montgomery form), with the sealing admin's identity key and
  signature, so an admin knows who shared it and the server can't substitute a key of its own.
  An account pins each organisation's key and newest policy version in its vault and refuses
  another key or an older policy.
* **Policy:** members (username and identity key), groups, device groups (by device key), rules
  and service workers, signed by the organisation key with a version, the hash of the version
  before it, and an expiry 30 days out. The server only stores a policy that follows the
  current one. Enrolled machines accept only a policy that verifies, is newer than the one they
  have, and hasn't expired.
* **Key rotation:** removing an admin replaces the organisation key. The old key signs the
  handover to the new one; enrolled machines follow that chain from the key they were enrolled
  with, and from then on ignore the old key.
* **Enrollment:** a service worker key (`sdw1-…`) carries the organisation's ID and public key
  and an Ed25519 worker secret. The agent creates its own device key; the worker signs a
  certificate for it, and the server checks the worker is in the current policy and not revoked
  or expired. The worker key only enrolls: it can't connect to anything.
* **Admission:** an enrolled machine lets in a member when the policy lists their username with
  the identity key in their device certificate, the server still has that device on that account,
  and a rule allows their group onto this machine's key. Enrolled machines can't be reached by ID
  or password and never start sessions.
* **Membership:** a member sees an organisation as an invitation until they join it, and can
  decline it.

## Everything else

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
* **Recovery key:** a second copy of the identity key is sealed under a 160-bit recovery key that
  is shown once at sign-up (`XXXX-XXXX-…`, with a checksum that catches typos). To reset a
  forgotten password, the client proves it holds the recovery key by signing a server challenge
  with a key derived from it, opens the recovery copy and re-seals it under the new password.
  The server can't open either copy or reset a password without the key. Recovery keys are
  single-use: a reset issues a new one. Without the password *and* the recovery key, the identity
  is lost by design.

## What the server sees

Who connects to whom, when, and how much data flows; device names and IDs; usernames, the
members of organisations and their rules (signed, so it can read them but not change them).
It never sees screens, input, clipboard or files, passwords (account or unattended), address
books, saved passwords, or any key that could open a session.
