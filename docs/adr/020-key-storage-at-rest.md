# ADR-020: Key Storage at Rest

## Status

Accepted (2026-11-12). **Implementation pending — ROADMAP T-08.**

## Context

`<data_dir>/identity.key` is a 96-byte plaintext file at mode 0600, and the
SQLCipher key is `SHA-256(b"mycelium-db-key:" ‖ identity_bytes)`. One file read
therefore yields the identity *and* every stored message, so encryption at rest
currently protects against nothing an attacker with filesystem access cannot
bypass.

Two separate problems: where the identity lives, and the fact that the database
key is a function of it.

## Decision

### The identity lives in platform key storage

- **Mobile** — Android Keystore and iOS Keychain, through the platform bridge.
  The key never lands in the app's data directory.
- **Desktop and OpenWRT** — the OS keyring where one exists (Secret Service,
  macOS Keychain), and a passphrase supplied at start where one does not.

The keyring-first choice is about unattended start: a daemon that cannot come
back after a reboot without someone typing a passphrase is a daemon that will
be run with the passphrase in a file, which is the plaintext key again with
extra steps. Where no keyring exists, the passphrase is the honest option and
the daemon refuses to run without it — no plaintext fallback, because a
fallback is what everything would use.

The limitation to state plainly: a keyring unlocked by the login session
protects against a stolen disk, not against code running as that user.

### The database gets its own key

A fresh random database key, stored wrapped by the same keystore, keyring or
passphrase as the identity. The database key stops being a function of the
identity, so a leak of either says nothing about the other, and the database
can be rekeyed without touching the identity.

Deriving through HKDF with a stored salt was the cheaper option and solves only
half of it: the salt is not secret, so an identity leak still yields the
database key. The asymmetry matters — the identity is the thing a user cannot
rotate.

### No migration while pre-release

A data directory written by an older build is refused, with a message saying
to re-onboard. The protocol is `0.1-draft` with no deployed nodes; an in-place
re-encryption would mean two copies of a secret on disk during the window where
it is most likely to fail, for data nobody outside development has.

This **replaces** T-08's acceptance bullet promising a migration without data
loss. The cost is local test history, and the trigger to revisit is the same as
the protocol version's: the first time a node runs on someone else's device.

## Consequences

**Easier:**

- Filesystem access no longer yields the identity on mobile, and on desktop it
  yields it only while the keyring is unlocked or the passphrase is known.
- Identity compromise and database compromise become separate events.

**Harder:**

- Three storage back ends (Keystore, Keychain, Secret Service) plus a
  passphrase path, each with its own failure modes, and all four must be
  exercised or the claim is untested on most of them.
- A passphrase-protected daemon cannot restart unattended. That is the
  intended trade, and it will be unpopular on OpenWRT.
- Refusing an old data directory is a destructive-feeling first run. The
  message has to say exactly what was refused and why, or it reads as
  corruption.
- The wrapped database key is a new file to lose. Losing it means losing the
  message history even with the identity intact, which is a failure mode the
  current derivation does not have.

## Alternatives Considered

1. **Passphrase everywhere, no keyring.** One path to implement and test, and
   unattended restart stops working on every desktop and router.
2. **Document the limitation and keep the 0600 file.** No work, and encryption
   at rest stays a claim the project does not make for desktop targets.
3. **HKDF the database key from the identity with a stored salt.** Smaller
   change; an identity leak still yields the database.
4. **Migrate in place with a backup.** Keeps local history, and holds two
   copies of a secret during the riskiest moment, for data that only exists on
   developer machines.
