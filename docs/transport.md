# fsh Transport Protocol

## Overview

The fsh transport layer provides a confidential, integrity-protected,
mutually-bound channel over which user authentication and connection
protocols run. It mirrors SSH's transport layer (RFC 4253) in purpose —
server authentication, session binding, and entry into services — but
delegates all key exchange, record protection, and forward secrecy to
QUIC version 1 with embedded TLS 1.3.

There is no fsh key exchange, no fsh record layer, no rekeying, and no
compression. A single QUIC connection carries one fsh session; QUIC
bidirectional streams carry connection-protocol channels.

Terms reused from RFC 4251: transport layer, host key, session
identifier, algorithm negotiation, name-list, service request.

## Transport (QUIC+TLS 1.3 profile)

Implementations MUST run over QUIC version 1 (RFC 9000) with TLS 1.3
(RFC 8446) as the only handshake. TLS 1.2 and below MUST NOT be
offered or accepted. QUIC version negotiation handles versioning;
there is no SSH-style version-string exchange.

- ALPN: endpoints MUST offer and select `fsh/1`. A server that does
  not recognize the ALPN MUST abort the connection. No other ALPN
  token is defined.
- TLS parameters: TLS 1.3 only. AEAD suites only:
  `tls-aes-128-gcm-sha256`, `tls-aes-256-gcm-sha384`,
  `tls-chacha20-poly1305-sha256` (TLS 1.3 cipher suites, lowercase-
  hyphenated per fsh naming, max 64 chars). Finite-field and
  elliptic-curve groups used inside the TLS handshake are a TLS
  concern, not fsh negotiation; implementations MUST NOT offer
  FFDHE groups below 3072 bits or non-NIST curves outside TLS policy.
- 0-RTT: clients MUST NOT send application data in 0-RTT. Servers
  MUST reject 0-RTT. Replay protection for session data comes from
  QUIC/TLS nonce handling, not fsh sequence numbers.
- Streams: each connection-protocol channel maps to one QUIC
  bidirectional stream. Stream-level and connection-level flow
  control is QUIC's; there is no fsh-level window. Stream reset and
  stop map to channel close semantics (see connection protocol).
- Keepalive: fsh defines no ping message. Idle detection uses QUIC
  PING frames and `max_idle_timeout` transport parameters.
  `SSH_MSG_IGNORE` MAY be sent as an application-level keepalive.
- Framing: fsh messages are sent as `byte msg-number || payload`
  over the negotiated stream or the session control stream (stream 0
  carries transport and userauth messages). There is no SSH binary
  packet length / padding / random padding layer; QUIC datagram and
  stream framing plus TLS AEAD replace it.
- Algorithm negotiation at the fsh layer: none. There is no
  `KEXINIT` name-list exchange for kex, host-key, encryption, MAC,
  or compression. Cipher/MAC choice is a TLS 1.3 handshake outcome.
  Public-key signature algorithms are negotiated in the user
  authentication protocol, not here.

## Host identity

TLS alone authenticates a certificate chain, which is insufficient
for fsh's server-identity model. Servers additionally own persistent
host keys, and clients pin them.

- Server host key types: `ssh-ed25519`, `ssh-ed448`,
  `ecdsa-sha2-nistp256`, `ecdsa-sha2-nistp384`,
  `ecdsa-sha2-nistp521`, `rsa-sha2-256`, `rsa-sha2-512`
  (RSA keys >= 3072 bits only), `sk-ssh-ed25519@openssh.com`,
  `sk-ecdsa-sha2-nistp256@openssh.com`. DSA, `ssh-rsa` (SHA-1),
  and RSA < 3072 bits MUST NOT be used.
- Presentation: on first contact the server sends its host key(s)
  on the control stream inside the service setup, before userauth.
  The host key material is bound to the TLS session via the channel
  binding below; a host key asserted over a different TLS session
  MUST be rejected.
- Verification: clients MUST verify the asserted host key against
  local trust storage (the known-hosts equivalent): a pinned
  fingerprint database keyed by hostname, port, and key algorithm.
  Trust-on-first-use (TOFU) with explicit user confirmation is the
  default policy; enterprise deployments MAY pre-provision pins.
  On mismatch the client MUST abort with `SSH_MSG_DISCONNECT`
  reason `host-key-changed` and MUST NOT proceed to userauth.
- Fingerprint format: SHA-256 over the raw public key blob,
  base64-encoded without padding, same canonical form as OpenSSH
  `SHA256:` fingerprints, so operators can compare out of band.
- Rotation: a server MAY assert multiple host keys (e.g. during
  algorithm migration). Clients SHOULD store all pinned keys per
  host and accept if any pin matches.

## Channel binding

All application-layer authentication is bound to the transport so a
signature captured on one session cannot be replayed on another.

- Session identifier: at handshake completion both sides compute
  `session-id = TLS-Exporter("fsh session id", handshake-hash, 32)`.
  The label is exactly `fsh session id` (14 chars). Length is 32
  bytes. It is constant for the life of the QUIC connection and
  MUST NOT be renegotiated (TLS key updates do not change it).
- Every userauth public-key signature MUST cover the session
  identifier concatenated with the request fields (see
  authentication protocol). Signatures that omit or mismatch the
  session identifier MUST be rejected.
- TLS exporters are the only binding source. No fsh `KEX-H`
  transcript hash exists.

## Message numbers

Transport owns 1-19 (generic) and 20-29 (negotiation). All other
ranges belong to userauth (50-79), connection (80-127), reservation
(128-191), and local extensions (192-255).

Generic (control stream):

| Number | Name                  | Notes                                  |
|--------|-----------------------|----------------------------------------|
| 1      | SSH_MSG_DISCONNECT    | Reason code + description; then close  |
| 2      | SSH_MSG_IGNORE        | No-op; keepalive-safe                  |
| 3      | SSH_MSG_UNIMPLEMENTED | Reply to unknown msg-number            |
| 4      | SSH_MSG_DEBUG         | `always-display` flag + text           |
| 5      | SSH_MSG_SERVICE_REQUEST | Service name: `fsh-userauth`, `fsh-connection` |
| 6      | SSH_MSG_SERVICE_ACCEPT  | Echo of accepted service name        |
| 7-19   | reserved              | MUST reply UNIMPLEMENTED if received   |

Negotiation (20-29): reserved for future transport extensions
(e.g. an `ext-info` equivalent). Currently no message in this range
is defined; endpoints MUST NOT send them and MUST reply
`SSH_MSG_UNIMPLEMENTED` if received. There is no `KEXINIT` (20),
`NEWKEYS` (21), or `KEXDH_*` (30-49) — those numbers MUST NOT be
reused.

Service setup: after the QUIC/TLS handshake the client sends
`SSH_MSG_SERVICE_REQUEST` with `fsh-userauth`; the server replies
`SSH_MSG_SERVICE_ACCEPT` and then asserts host keys. `fsh-connection`
runs only after userauth success.

## Security properties

- Confidentiality and integrity: provided by TLS 1.3 AEAD records
  inside QUIC packets. fsh adds no cipher or MAC of its own.
- Replay protection: QUIC packet-number / TLS-nonce uniqueness
  plus TLS handshake transcript integrity. fsh sequence numbers do
  not exist.
- Forward secrecy: every session uses ephemeral TLS 1.3 key shares;
  compromise of long-term host or user keys does not decrypt past
  sessions.
- No downgrade: only one QUIC version handshake and one TLS
  version (1.3) with an AEAD-only suite policy and a single ALPN
  token. There is no version-string or name-list haggling an
  attacker can weaken; failed negotiation aborts rather than falls
  back.
- Server authentication: two layers — TLS handshake integrity plus
  host-key pinning with channel binding. Either layer failing aborts
  the session before userauth.
- Rekeying: unnecessary. TLS 1.3 key updates (QUIC key phases)
  rotate traffic keys transparently; fsh defines no `NEWKEYS` and
  no 1 GiB rekey threshold.

## SSH differences (what was dropped and why)

Mirrored on RFC 4253; dropped where QUIC + TLS 1.3 absorbs the need:

- Key exchange (`KEXINIT`, `KEXDH_*`, `NEWKEYS`, Diffie-Hellman
  group negotiation): dropped. TLS 1.3 performs an audited,
  ephemeral handshake; a second fsh kex would add code and attack
  surface for zero security gain.
- Record protection (ciphers, MACs, compression negotiation,
  sequence numbers): dropped. QUIC packet protection + TLS AEAD
  provide confidentiality, integrity, and replay resistance.
  Separate fsh packet length / padding is redundant.
- Rekeying (~1 GiB / time-based): dropped. QUIC key updates rotate
  keys without an fsh-visible handshake.
- Compression: dropped. Modern payloads (already compressed media,
  encrypted streams) gain nothing; compression-before-encryption
  invites CRIME-style oracles. Transport parameters negotiate
  nothing about compression.
- Version-string exchange and extensible `KEXINIT` name-lists:
  dropped. ALPN `fsh/1` plus the TLS handshake negotiate the only
  parameters that vary. Public-key algorithm choice lives in
  userauth, where the key types above apply.
- Hostbased / certificate-model server auth via SSH host-key
  signature over `KEX-H`: replaced by host-key assertion bound to
  the TLS exporter (channel binding) plus client-side pin storage.
  Fingerprint format stays OpenSSH-compatible for operability.

Kept from SSH: host-key pinning semantics, session-identifier
binding of authentication signatures, service-request multiplexing
(`fsh-userauth`, `fsh-connection`), and the 1-19 generic message
block discipline shared with the registry.
