# fsh Architecture

Mirrors RFC 4251 (SSH architecture). Adapts the three-layer model to
QUIC + TLS 1.3 transport with modern-only cryptography.

## 1. Overview

fsh provides secure remote login, command execution, and subsystem
invocation (including `fcp` file copy) over QUIC. Like SSH, it is
layered:

```
transport -> user authentication -> connection
```

All three layers run over a single QUIC connection. QUIC provides the
reliable, multiplexed stream substrate; TLS 1.3 provides handshake
secrecy, authentication framing, and record protection. fsh specifies
only what TLS 1.3 and QUIC do not already provide: host identity
policy, user authentication, and channel semantics.

Message numbers 1-255 are partitioned by layer (see Section 3):

* transport: 1-19 generic, 20-29 negotiation
* user authentication: 50-59 generic, 60-79 method-specific
* connection: 80-89 generic, 90-127 channel
* 128-191: reserved
* 192-255: local extensions

Algorithm names are lowercase-hyphenated, max 64 chars. Local
extensions MUST use `name@fqdn` form.

## 2. Layers

### 2.1 Transport layer

Runs directly over QUIC, inside TLS 1.3 protection. Responsibilities:

* Version and capability framing (minimal; no SSH-style banner or
  KEXINIT exchange).
* Server host identity: presentation (raw public key or certificate)
  plus client-side fingerprint/trust storage beyond the cert chain.
* Channel binding: binds application data (userauth signatures,
  session identifiers) to the concrete TLS exporter / QUIC connection
  IDs.
* Session identifier derivation: a unique per-connection value
  exported from the TLS handshake, used by upper layers.

TLS 1.3 absorbs what RFC 4253 assigns to transport: key exchange,
server authentication of the handshake, record
confidentiality/integrity (AES-GCM / ChaCha20-Poly1305 only), forward
secrecy, and rekeying (TLS key update). fsh specifies NO kex
algorithms, NO ciphers/MACs beyond the TLS 1.3 AEAD set, NO rekey at
~1 GiB, and NO compression.

### 2.2 User authentication protocol

Runs over the QUIC connection after transport establishment.
Responsibilities:

* Service request multiplexing (`fsh-userauth`, `fsh-connection`
  service names).
* Single supported method: `publickey` (message 50/51/52 framing plus
  method-specific 60 probe/verify), including FIDO2-backed
  `sk-ssh-ed25519` and `sk-ecdsa-sha2` keys as key types, not separate
  methods.
* Publickey probe-then-sign flow: client proves possession by signing
  over the session identifier plus request fields; server checks
  authorization (account key list) before signaling success.

No other methods exist: no password, hostbased, keyboard-interactive,
or none.

### 2.3 Connection protocol

Runs after successful user authentication. Responsibilities:

* Channels mapped 1:1 onto QUIC bidirectional streams. Stream open is
  channel open; stream close is channel close.
* Channel lifecycle messages: OPEN (90), CONFIRMATION (91), FAILURE
  (92), DATA (94), EOF (96), CLOSE (97). No WINDOW_ADJUST (93): QUIC
  stream and connection flow control replaces SSH windowing.
* Channel requests (message 98): `exec`, `shell`, `subsystem`
  (including `fcp`), `signal`, `exit-status`, `exit-signal`, plus
  minimal `pty-req` for interactive shells.
* Global messages (80-82) kept minimal; no forwarding requests.

Dropped from RFC 4254: `tcpip-forward` / `direct-tcpip`, X11
forwarding, environment passing, and window management.

## 3. Terminology

Reuses RFC 4251 terms with fsh bindings:

| Term | Meaning in fsh |
| ---- | -------------- |
| transport layer | QUIC + TLS 1.3 substrate; host identity, session identifier, channel binding |
| user authentication protocol | publickey-only client authentication over the transport |
| connection protocol | channel multiplexing over QUIC streams; exec/shell/subsystem |
| channel | one QUIC bidirectional stream plus fsh open/close/request state |
| service request | `fsh-userauth` / `fsh-connection` service selector |
| host key | server long-term identity key (modern-only types below) |
| session identifier | per-connection unique value derived from the TLS handshake |
| algorithm negotiation | TLS 1.3 negotiation plus fsh publickey-algorithm / subsystem name-lists |
| name-list | comma-separated algorithm/key/request names in negotiation messages |

Supported host/user key types: `ssh-ed25519`, `ssh-ed448` (where
practical), `ecdsa-sha2-nistp256/384/521`, RSA >= 3072 with SHA-2
(`rsa-sha2-256`, `rsa-sha2-512`), `sk-ssh-ed25519@openssh.com`,
`sk-ecdsa-sha2-nistp256@openssh.com`. Excluded: `ssh-dss`, RSA < 3072,
`ssh-rsa` (SHA-1).

## 4. Session lifecycle

1. QUIC + TLS 1.3 handshake. Client validates server host key
   (certificate chain and/or pinned fingerprint / trust store on
   first use). Both sides derive the session identifier.
2. Service request for `fsh-userauth`. Server advertises supported
   publickey algorithms as a name-list.
3. User authentication: optional publickey probe (method 60 OK reply),
   then signed USERAUTH_REQUEST (50). FAILURE (51) carries the
   continuable method list (always `publickey`); SUCCESS (52) advances.
4. Service request for `fsh-connection`. Either side opens channels =
   QUIC streams (90/91/92).
5. Channel operation: requests (98: exec/shell/subsystem/pty/signal),
   DATA (94), EOF (96), exit-status, CLOSE (97).
6. Connection teardown: close streams, then the QUIC connection.
   No session resumption carries authentication across connections;
   each new QUIC connection re-authenticates.

## 5. Security properties

* Mutual authentication: server via TLS 1.3 host identity (+ local
  trust policy); client via publickey signature bound to the session
  identifier (channel binding defeats replay across connections).
* Confidentiality + integrity: inherited from TLS 1.3 AEAD; fsh adds
  no record layer and MUST NOT negotiate weaker primitives.
* Forward secrecy: inherited from (EC)DHE in TLS 1.3; no static-kex
  fallback.
* No downgrade: single TLS 1.3 stack, single publickey mechanism,
  single channel model. Negotiation name-lists contain only
  modern-only entries, so there is no legacy option to force.
* Replay protection: QUIC packet protection plus session-identifier
  binding of auth signatures; signatures are invalid on any other
  connection.

## 6. Non-goals

Explicitly out of scope; MUST NOT be added without a new architecture
revision:

* TCP/IP forwarding (`tcpip-forward`, `direct-tcpip`) and X11
  forwarding.
* Password, hostbased, keyboard-interactive, and none authentication.
* Legacy cryptography: DSA (`ssh-dss`), RSA < 3072, `ssh-rsa`
  (SHA-1), CBC-era ciphers, non-AEAD suites, custom kex/compression.
* Compatibility fallback or version-downgrade paths.
* Environment passing beyond the minimal pty/shell contract.
* OS-agent or keychain integration beyond raw key-type support
  (handled elsewhere, not by the protocol layers).
