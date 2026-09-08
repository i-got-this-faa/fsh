# fsh User Authentication Protocol

Replaces RFC 4252. Publickey-only authentication over the fsh secure
transport (QUIC + TLS 1.3). All method and message numbers follow the
shared registry: auth generic 50-59, method-specific 60-79.

## 1. Overview

Authentication runs after the transport handshake, inside the
confidential, integrity-protected QUIC connection. One party is the
client (proves identity); the other is the server (authorizes access).

- Service name: `fsh-userauth`. The client requests it via the
  transport service-request mechanism before sending any auth message.
- Follow-on service on success: `fsh-connection`.
- Single method: `publickey` (includes FIDO2 `sk-*` keys as key
  types, not separate methods). No other method exists.
- Usernames are UTF-8, max 256 bytes, case-sensitive. Empty user is
  invalid; servers MUST reject it.
- Algorithm names are lowercase-hyphenated, max 64 chars. Local
  extensions use `name@fqdn` form.
- Session identifier: 32+ bytes derived from the TLS 1.3 handshake
  (exporter with a fixed label, see transport doc). All signatures
  cover it. It binds authentication to this connection; replays on
  another connection fail verification.

## 2. Message flow

Generic messages (50-59). All strings are `string` (uint32 length +
bytes); `boolean` is one byte (`0`/`1`); `name-list` is a
comma-separated string list.

```
byte      SSH_MSG_USERAUTH_REQUEST       50
string    user name
string    service name ("fsh-connection")
string    method name ("publickey")
...       method-specific fields
```

```
byte      SSH_MSG_USERAUTH_FAILURE       51
name-list authentications that can continue
boolean   partial success (MUST be 0; no partial success in fsh)
```

```
byte      SSH_MSG_USERAUTH_SUCCESS       52
(no payload)
```

Flow:

1. Client sends `USERAUTH_REQUEST(50)` for each attempt. Method field
   is always `"publickey"`.
2. Server replies `SUCCESS(52)` (access granted, proceed to
   `fsh-connection`) or `FAILURE(51)` (attempt rejected, may retry).
3. `FAILURE` continuations list contains exactly `"publickey"`.
   Clients MUST NOT interpret any other name; servers MUST NOT send
   any other name.
4. Unrecognized methods: server MUST reply `FAILURE(51)` with
   `["publickey"]`. There is no fallback negotiation.
5. Servers SHOULD rate-limit and cap consecutive failures (RECOMMENDED:
   10 attempts, then drop the connection) to blunt online guessing of
   authorized-key identities.

## 3. Publickey method

Method name: `publickey`. Two steps: probe, then signed request.
Both use `USERAUTH_REQUEST(50)` with a boolean flag distinguishing
them. Method-specific reply: `SSH_MSG_USERAUTH_PK_OK(60)`.

### 3.1 Probe (key acceptability check)

```
byte      50
string    user name
string    service name ("fsh-connection")
string    "publickey"
boolean   FALSE
string    public-key algorithm name
string    public-key blob
```

Server replies:

```
byte      SSH_MSG_USERAUTH_PK_OK         60
string    public-key algorithm name
string    public-key blob
```

- Server sends `PK_OK(60)` iff the algorithm is supported AND the key
  is authorized for the user. Otherwise it sends `FAILURE(51)`.
- `PK_OK` is advisory only. It grants nothing and MUST NOT be treated
  as authentication.
- Clients SHOULD probe before signing (avoids pointless signatures,
  hides which key would sign from a non-authorizing server), but MAY
  skip the probe and send the signed request directly.

### 3.2 Signed request

```
byte      50
string    user name
string    service name ("fsh-connection")
string    "publickey"
boolean   TRUE
string    public-key algorithm name
string    public-key blob
string    signature
```

Signature input (signed blob) is:

```
string    session identifier
byte      50
string    user name
string    service name ("fsh-connection")
string    "publickey"
boolean   TRUE
string    public-key algorithm name
string    public-key blob
```

- The signature MUST cover the session identifier first, then the
  exact request fields above, in order, in wire encoding.
- Server verifies and replies `SUCCESS(52)` or `FAILURE(51)`.
- A `PK_OK(60)` received without a preceding probe (unsolicited) MUST
  be ignored.

## 4. Key types

### 4.1 Supported

| Wire name              | Key / signature scheme              | Notes                          |
|------------------------|-------------------------------------|--------------------------------|
| `ssh-ed25519`          | Ed25519                             | RECOMMENDED default            |
| `ssh-ed448`            | Ed448                               | where implementation provides  |
| `ecdsa-sha2-nistp256`  | ECDSA P-256 + SHA-256               |                                |
| `ecdsa-sha2-nistp384`  | ECDSA P-384 + SHA-384               |                                |
| `ecdsa-sha2-nistp521`  | ECDSA P-521 + SHA-512               |                                |
| `rsa-sha2-256`         | RSA >= 3072 bit + SHA-256 (PSS)     | keys < 3072 bit MUST be refused|
| `rsa-sha2-512`         | RSA >= 3072 bit + SHA-512 (PSS)     | keys < 3072 bit MUST be refused|
| `sk-ssh-ed25519`       | FIDO2 Resident/non-resident Ed25519 | wire includes flags, counter,  |
| `sk-ecdsa-sha2-*`      | FIDO2 ECDSA (P-256)                 | `sk-ecdsa-sha2-nistp256`; attested |

Rules:

- RSA keys shorter than 3072 bits MUST be refused at parse time.
- RSA signatures MUST use SHA-2 (PSS preferred, PKCS#1 v1.5 with
  SHA-256/512 accepted). SHA-1 (`ssh-rsa`) is not a name in this
  protocol.
- `sk-*` blobs carry the authenticator data (flags, counter, UV
  extension output) per the existing OpenSSH `sk-*` encoding; the
  signature covers the same blob as other types. Servers SHOULD check
  the user-verification (UV) flag against local policy.
- Unknown key-type names: server MUST reply `FAILURE(51)`, never
  `PK_OK(60)`.

### 4.2 Excluded

The following are NOT key types or methods in fsh and MUST NOT be
implemented:

- `ssh-dss` (DSA): insecure key size; removed.
- `ssh-rsa` (RSA + SHA-1): broken hash; use `rsa-sha2-*`.
- RSA keys < 3072 bit, regardless of hash.
- `ssh-rsa-cert-v01`, `ssh-ed25519-cert-v01` (OpenSSH certificates):
  no cert-based user auth in this revision (host identity is handled
  at the transport layer; see transport doc).
- Any password, hostbased, keyboard-interactive, or `none` material:
  those are authentication methods, not key types, and are dropped
  entirely (see section 6).

## 5. Verification

On each signed `USERAUTH_REQUEST(50)` the server MUST, in order:

1. Reject malformed packets (bad lengths, trailing bytes, empty user,
   unknown/unsupported algorithm name) with `FAILURE(51)`.
2. Reject excluded key material (DSA, `ssh-rsa`, RSA < 3072 bit) with
   `FAILURE(51)`, without signature verification.
3. Look up the user; unknown users get `FAILURE(51)`. Implementations
   SHOULD take constant time to this point where practical (do not
   leak user existence via timing beyond what the probe already
   reveals by design).
4. Check the key blob is authorized for the user (authorized-keys
   store or equivalent). Unauthorized: `FAILURE(51)`.
5. Reconstruct the signed blob (session identifier + request fields,
   section 3.2) and verify the signature with the presented public
   key. Invalid: `FAILURE(51)`.
6. Apply local authorization policy (account locked, source
   restrictions, UV policy for `sk-*`). Denied: `FAILURE(51)`.
7. On pass: reply `SUCCESS(52)` and bind the connection to
   (user, key, session identifier). The binding MUST NOT migrate to
   another QUIC connection.

Notes:

- Servers MUST verify the session identifier matches the current
  connection. A signature over any other value MUST fail.
- Servers MUST NOT accept a signature that omits or reorders signed
  fields.
- Replay within the same connection: each signed request is a fresh
  authentication decision; a previously observed (session-id, blob,
  signature) tuple MUST NOT be cached as success for a different user
  or service.

## 6. SSH differences (dropped methods and why)

RFC 4252 defines `publickey`, `password`, `hostbased`,
`keyboard-interactive`, and `none`. fsh keeps `publickey` only.

| Dropped             | Why                                                        |
|---------------------|------------------------------------------------------------|
| `password`          | Phishable, guessable, needs server-side secrets; public keys + FIDO2 cover human and automated use. |
| `keyboard-interactive` | Password/OTP prompting over the auth channel; same secrets problem, plus interactive downgrade surface. |
| `hostbased`         | Trusts client host keys for user auth; fragile delegation, confusing semantics. |
| `none`              | Grants access without proof; only ever useful for probing, which `FAILURE` continuations already handle. |
| `ssh-rsa` / DSA / short RSA | Legacy crypto; TLS 1.3 transport is modern-only, auth matches it. |
| `tcpip-forward`, `direct-tcpip`, `x11`, compression | Not auth-layer, but excluded protocol-wide: forwarding/compression belong to other layers or not at all. No auth method may request them. |

Consequences:

- No `SSH_MSG_USERAUTH_PASSWD_CHANGEREQ(60)` equivalent. That number
  (60) is reused for `PK_OK` in the method-specific block (60-79).
- No partial success (`FAILURE` boolean always 0). Single method
  means authentication either succeeds fully or fails.
- No banner message (`SSH_MSG_USERAUTH_BANNER`, RFC 4252 section
  5.4): pre-auth text is a phishing aid; servers with a legal notice
  SHOULD present it at connection-open or MOTD instead.
