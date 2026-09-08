# fsh docs

QUIC-based SSH alternative. Secure and blazingly fast.

## Layout

- `bin/fsh` — client
- `bin/fshd` — server daemon
- `bin/fcp` — file copy tool
- `crates/*` — shared libraries (`fsh-core`)
- `docs/` — design docs

## Protocol docs

- `docs/architecture.md` — layer architecture (transport, userauth, connection).
- `docs/transport.md` — QUIC + TLS 1.3 transport and host identity.
- `docs/authentication.md` — public-key-only user authentication.
- `docs/connection.md` — channels over QUIC streams (sessions, exec, fcp).
- `docs/numbers.md` — assigned message numbers, algorithm and service names.
