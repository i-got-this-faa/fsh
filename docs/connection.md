# fsh Connection Protocol

Service name: `fsh-connection`. Runs after transport establishment and
user authentication, multiplexed over the authenticated QUIC connection.

## Overview

The connection protocol provides interactive and non-interactive command
execution. One channel type exists: `session`. Each session channel carries
at most one of `shell`, `exec`, or `subsystem`. Exit state and signals are
reported as channel requests.

Message numbers:

- 80-82: global requests.
- 90-97: channel open / data / close.
- 98-100: channel requests and replies.

All messages are sent on the control stream except channel payload, which
travels on the channel's own QUIC stream (see below).

## Channels over QUIC streams

A channel IS a QUIC bidirectional stream. Opening a channel = opening a
stream and sending `CHANNEL_OPEN`; closing = sending `CHANNEL_CLOSE` and
closing the stream.

- Either side MAY open a channel at any time after authentication.
- Each endpoint numbers its channels independently with uint32 local ids.
  The pair (initiator, local id) maps 1:1 to a QUIC stream id. Channel ids
  MUST NOT be reused within a connection.
- Channel types: only `session`. Unknown types MUST be rejected with
  `CHANNEL_OPEN_FAILURE` (reason 3, "unknown channel type").
- Flow control is QUIC stream/connection flow control (`MAX_DATA`,
  `MAX_STREAM_DATA`). There is no window mechanism in fsh.
- Directional shutdown maps to EOF: `FIN` on the send part of a stream is
  equivalent to `CHANNEL_EOF`. After both directions are closed the stream
  is discarded; no further messages for that channel are valid.

## Channel messages

| #  | Name                   | Notes                                          |
|----|------------------------|------------------------------------------------|
| 90 | CHANNEL_OPEN           | type name, sender channel, initial reserved    |
| 91 | CHANNEL_OPEN_CONFIRM   | recipient channel, sender channel              |
| 92 | CHANNEL_OPEN_FAILURE   | recipient channel, reason code, description    |
| 93 | WINDOW_ADJUST          | RESERVED. MUST NOT send; MUST ignore on receipt|
| 94 | CHANNEL_DATA           | payload bytes on the channel's QUIC stream     |
| 95 | CHANNEL_EXTENDED_DATA  | only type 1 (stderr); others MUST be rejected  |
| 96 | CHANNEL_EOF            | no more data will be sent; maps to stream FIN  |
| 97 | CHANNEL_CLOSE          | channel teardown; maps to stream close         |

`CHANNEL_OPEN` carries: channel type (`session`), sender channel id, and a
reserved uint32 (MUST be 0; replaces the SSH window/packet-size fields).
Receivers MUST ignore the reserved field.

`CHANNEL_OPEN_FAILURE` reason codes follow SSH (`1` administratively
prohibited, `2` connect failed, `3` unknown channel type, `4` resource
shortage). fsh adds no new codes.

`CHANNEL_DATA` / `CHANNEL_EXTENDED_DATA` are framing markers only; the
bytes themselves are the QUIC stream payload. One DATA message corresponds
to one contiguous stream segment.

## Channel requests (kept + dropped)

Request framing: msg 98 (`CHANNEL_REQUEST`: recipient channel, type name,
want-reply, type data), 99 (`CHANNEL_SUCCESS`), 100 (`CHANNEL_FAILURE`).
`want-reply` follows SSH semantics; exit and signal notifications use
`want-reply = false`.

Kept:

- `shell` — interactive shell. Requires a prior `pty-req` for terminal
  use; without one the server MAY attach a dumb pipe instead of failing.
- `exec` — single command; data is the command string (UTF-8, max 16 KiB).
- `subsystem` — only value `fcp` (file copy). All other names MUST fail.
- `pty-req` — minimal allocation for interactive shell: `TERM` (max 64
  chars), width/height in chars, width/height in pixels, empty modes list.
  Non-empty terminal modes MUST be rejected.
- `window-change` — pty resize companion to `pty-req` only. MUST be ignored
  on channels without a pty.
- `signal` — signal name (e.g. `TERM`, `KILL`, `INT`, `HUP`); delivers to
  the process group of the session.
- `exit-status` — uint32 exit code, server to client, terminal state.
- `exit-signal` — signal name + core-dumped flag + message + language tag,
  server to client, terminal state. Mutually exclusive with `exit-status`.

Dropped (server MUST reject with `CHANNEL_FAILURE`):

- `env` — no environment passing. Locale and caller environment are never
  forwarded; the server exec environment is fixed by policy.
- `x11-req`, `x11-fwd` — no X11 forwarding.
- `xon-xoff` — no flow-control override.
- `auth-agent-req@openssh.com` and any forwarding bindings — no agent
  forwarding.
- Any `tcpip-forward`, `direct-tcpip`, `forwarded-tcpip` channel types or
  requests — no TCP forwarding of any kind.

## Sessions (shell/exec/subsystem)

A `session` channel carries exactly one program binding:

1. Client sends `CHANNEL_OPEN` (`session`) and receives
   `CHANNEL_OPEN_CONFIRM`.
2. Client sends at most one of `shell`, `exec`, or `subsystem`. A second
   binding request on the same channel MUST fail. Implementations MAY close
   the channel after the second attempt.
3. Optional `pty-req` MUST precede `shell` when a terminal is wanted;
   `pty-req` before `exec` requests a pty for that command and MAY be
   refused by policy. `pty-req` with `subsystem` MUST be refused.
4. Data flows over the channel's stream: stdin/stdout as `CHANNEL_DATA`,
   stderr as `CHANNEL_EXTENDED_DATA` type 1.
5. Termination: server sends exactly one of `exit-status` or `exit-signal`,
   then `CHANNEL_EOF` and `CHANNEL_CLOSE`. Client closes its send direction
   when stdin ends, then the channel with `CHANNEL_CLOSE` after reading EOF.

Global requests (80 `GLOBAL_REQUEST`, 81 `REQUEST_SUCCESS`,
82 `REQUEST_FAILURE`): no forwarding or listener requests exist. The only
permitted global request is `keepalive@fsh.dev` (`want-reply = true`,
empty data) for dead-peer detection. All other global requests MUST fail
with `REQUEST_FAILURE`.

## SSH differences

| SSH (RFC 4254)              | fsh                                        |
|-----------------------------|--------------------------------------------|
| Channels multiplex one TCP stream | Each channel is a QUIC bidi stream  |
| `WINDOW_ADJUST` (93) flow control | Dropped; QUIC flow control only     |
| `OPEN` window / max-packet fields | Reserved uint32, MUST be 0         |
| `env` request               | Dropped                                    |
| `x11-req`, X11 channels     | Dropped                                    |
| `tcpip-forward`, `direct-tcpip`, `forwarded-tcpip`, `auth-agent-req` | Dropped; no forwarding of any kind |
| Arbitrary subsystems        | Only `fcp`                                 |
| `xon-xoff`                  | Dropped                                    |
| Compression negotiation     | None; QUIC handles the path                |
| Rekey / sequence replay     | None; TLS 1.3 key update governs           |

Numbers unchanged from SSH: 80-82 global, 90-97 channel lifecycle,
98-100 channel requests. Message 93 is reserved and never sent.
