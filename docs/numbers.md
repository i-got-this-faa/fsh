# fsh Assigned Numbers

Mirrors RFC 4250 for fsh: QUIC + TLS 1.3 transport, mutual auth,
modern-only crypto. No legacy, no compat fallback.

## Message number blocks

Message numbers 1-255, partitioned by layer. All writers MUST use
these blocks consistently. Numbers outside a layer's blocks MUST NOT
be sent for that layer.

| Block   | Layer      | Use                        |
|---------|------------|----------------------------|
| 1-19    | transport  | generic (disconnect, ignore, debug, service negotiation) |
| 20-29   | transport  | negotiation and handshake framing |
| 30-49   | —          | unassigned (SSH kex range; no equivalent in fsh) |
| 50-59   | auth       | generic userauth messages  |
| 60-79   | auth       | method-specific messages   |
| 80-89   | connection | generic (global requests)  |
| 90-127  | connection | channel operations         |
| 128-191 | —          | reserved; MUST NOT assign without a protocol revision |
| 192-255 | —          | local extensions only      |

TLS 1.3 absorbs key exchange, record protection, and rekey; QUIC
absorbs reliability and stream flow control. Blocks are retained for
framing shape even where fsh defines no message in them.

## Initial assignments

A receiver MUST ignore an unknown message whose number falls in an
assigned block, and MUST disconnect on a number in a reserved block.
`—` means the number is retained but has no fsh message.

Transport, generic (1-19):

| Number | Message       | Notes                          |
|--------|---------------|--------------------------------|
| 1      | DISCONNECT    | error text + reason code       |
| 2      | IGNORE        | keepalive / traffic shaping    |
| 3      | UNIMPLEMENTED | response to unknown sequence   |
| 4      | DEBUG         | human-readable only            |
| 5      | SERVICE_REQUEST | request `fsh-userauth` / `fsh-connection` |
| 6      | SERVICE_ACCEPT  | accept a requested service     |
| 7      | EXT_INFO      | extension negotiation, optional |
| 8-19   | unassigned    |                                |

Transport, negotiation (20-29): 20-29 reserved for handshake
framing and channel binding. No initial assignment; kex, NEWKEYS,
and compression messages do not exist in fsh.

Auth, generic (50-59):

| Number | Message          |
|--------|------------------|
| 50     | USERAUTH_REQUEST |
| 51     | USERAUTH_FAILURE |
| 52     | USERAUTH_SUCCESS |
| 53     | USERAUTH_BANNER  |
| 54-59  | unassigned       |

Auth, method-specific (60-79):

| Number | Message         | Method     |
|--------|-----------------|------------|
| 60     | USERAUTH_PK_OK  | publickey probe |
| 61-79  | unassigned      |            |

Password, hostbased, keyboard-interactive, and none have no
messages. New methods, if ever defined, take numbers from 61-79.

Connection, generic (80-89):

| Number | Message         |
|--------|-----------------|
| 80     | GLOBAL_REQUEST  |
| 81     | REQUEST_SUCCESS |
| 82     | REQUEST_FAILURE |
| 83-89  | unassigned      |

No global request names are initially defined (no forwarding).

Connection, channel (90-127):

| Number  | Message            | Notes                          |
|---------|--------------------|--------------------------------|
| 90      | OPEN               | only `session` channel type    |
| 91      | OPEN_CONFIRMATION  |                                |
| 92      | OPEN_FAILURE       |                                |
| 93      | —                  | WINDOW_ADJUST dropped; QUIC flow control replaces it; MUST NOT send |
| 94      | DATA               | per-stream bytes               |
| 95      | EXTENDED_DATA      | type 1 (stderr) only           |
| 96      | EOF                | half-close                     |
| 97      | CLOSE              |                                |
| 98      | CHANNEL_REQUEST    | `shell`, `exec`, `subsystem`, `pty-req`, `signal`, `exit-status`, `exit-signal` |
| 99      | CHANNEL_SUCCESS    |                                |
| 100     | CHANNEL_FAILURE    |                                |
| 101-127 | unassigned         |                                |

Extended data types: 1 = stderr. No other type is defined.

## Algorithm names

Public-key / signature algorithms only. TLS 1.3 negotiates bulk
ciphers itself; no transport cipher, MAC, or compression names exist.

| Name | Key type | Notes |
|------|----------|-------|
| `ssh-ed25519` | Ed25519 | RECOMMENDED |
| `ssh-ed448` | Ed448 | where practical |
| `ecdsa-sha2-nistp256` | ECDSA P-256 | |
| `ecdsa-sha2-nistp384` | ECDSA P-384 | |
| `ecdsa-sha2-nistp521` | ECDSA P-521 | |
| `rsa-sha2-256` | RSA, >= 3072 bits, SHA-2 | keys < 3072 bits MUST be rejected |
| `rsa-sha2-512` | RSA, >= 3072 bits, SHA-2 | keys < 3072 bits MUST be rejected |
| `sk-ssh-ed25519@openssh.com` | FIDO2 Ed25519 | U2F/FIDO2 resident or bound key |
| `sk-ecdsa-sha2-nistp256@openssh.com` | FIDO2 ECDSA P-256 | U2F/FIDO2 bound key |

Excluded, MUST NOT offer or accept: `ssh-dss`, `ssh-rsa`
(SHA-1), RSA keys under 3072 bits, passwords, hostbased,
keyboard-interactive, `none`, X11/TCP forwarding, compression.

Channel type: `session` only. Subsystem: `fcp` (file copy tool).
Channel request names: `shell`, `exec`, `subsystem`, `pty-req`
(minimal, interactive shell only), `signal`, `exit-status`,
`exit-signal`. No `tcpip-forward`, `direct-tcpip`, `x11`, or `env`.

## Service names

| Name | Purpose |
|------|---------|
| `fsh-userauth` | user authentication protocol (replaces `ssh-userauth`) |
| `fsh-connection` | connection protocol (replaces `ssh-connection`) |

Requested via SERVICE_REQUEST (5) / accepted via SERVICE_ACCEPT
(6). Authentication MUST complete under `fsh-userauth` before
`fsh-connection` is requested.

## Naming rules

Applies to algorithm, service, channel-type, request, subsystem,
and extension names:

- Printable US-ASCII only; no `@`, comma, or whitespace except as
  the single `@` separator in local names.
- Case-sensitive; lowercase-hyphenated for standard names.
- Max 64 characters including any `@` suffix.
- Local extensions MUST take the form `name@FQDN`, where FQDN is a
  domain the definer controls (e.g. `zerortt@example.com`).
- Standard names MUST NOT contain `@`. A name with `@` MUST be
  treated as local even inside 1-191 blocks.
- Message numbers 192-255 are local extensions only and MUST pair
  with a `name@FQDN` identifier in the payload.

## Registry

STANDARDS-ACTION-style discipline, adapted for a single-repo spec:

- New assignments in 1-127 and 128-191 require a protocol-doc
  update describing the message or name, its wire format, and
  which layer sends it. Unreviewed or undocumented use is
  non-conforming, even experimentally.
- Numbers and names, once assigned, are never reused or
  redefined. Deprecated items are marked HISTORIC, never removed
  from the tables.
- 128-191 stays reserved until a protocol revision assigns it;
  implementations MUST disconnect on receipt.
- 192-255 and any `name@FQDN` need no central approval but MUST
  NOT collide with assigned numbers or standard names, and MUST
  NOT be sent unless the peer advertised support (EXT_INFO or
  explicit configuration).
- All five protocol docs MUST use the block and naming rules in
  this document; on conflict, this document wins for numbers
  and names.
