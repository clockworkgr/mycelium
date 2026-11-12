# ADR-017: Channel Message Row Identity

## Status

Accepted (2026-11-12). **Implementation pending — ROADMAP T-14.**

## Context

ADR-013 re-keyed the channel flood on a digest of the message — id, source,
channel, content type and body — so a copy sharing only the envelope's
cleartext `message_id` can no longer stop the genuine message propagating.

Storage was not re-keyed with it. `channel_messages` has `message_id` as its
primary key and `store_channel_message` is an `INSERT OR IGNORE`, so whichever
copy arrives first keeps the row. A relay carrying a channel message can
therefore still decide what this node's own history says it contained: the
genuine message is forwarded onward, but locally the forgery stays.

## Decision

### The row is keyed on the flood digest

The primary key becomes the digest the flood is deduplicated on, with the
envelope's `message_id` kept as an ordinary column. Two copies that differ in
anything the reader sees are then two rows, and the one the user reads is no
longer decided by arrival order. A migration moves existing rows; their digests
are computable from the columns already stored.

### Authentication is a separate task

The durable answer is that a channel message should be signed by its source, so
a forgery is not storable in the first place. That needs a wire change and a
key-availability story for public channels — a reader may hold no key for a
poster it has never met — and it is the same question ADR-014 answers for
emergency broadcasts. It is therefore its own task rather than a condition of
this one: re-keying the row is cheap, closes the suppression for good, and does
not pre-empt how authentication is designed.

Until then the row faithfully stores whichever message arrived, forged or not,
which is what a public unauthenticated board is.

## Consequences

**Easier:**

- A forged copy can no longer displace a genuine message in local history, and
  the storage identity matches the flood identity, so the two layers stop
  disagreeing about what "the same message" means.

**Harder:**

- A schema migration on a table that may already hold rows, and the digest
  must be computed the same way in the storage layer as in the flood layer —
  one definition, used twice, or they will drift.
- Two rows can now hold the same `message_id`, so anything reading by that id
  must say which one it means. Receipts and moderation both reference ids.
- Channel messages stay forgeable, so this fixes suppression and not
  authenticity. The spec's §9.4 gap list has to say so plainly rather than
  implying the storage fix closed it.

## Alternatives Considered

1. **Authenticate channel messages now.** Fixes suppression and forgery
   together; a wire change plus a key-availability design, which would hold the
   cheap half hostage to the expensive one.
2. **Leave the row keyed on the envelope id.** No migration, and local history
   can silently keep a forgery in place of a real message.
3. **Store both copies under a composite key of id and digest.** Equivalent in
   effect to keying on the digest, with a wider key and no extra property.
