# ADR-010: Verified Co-Signatures for Level-3 Emergency Broadcasts

## Status

Accepted (2026-11-10)

## Context

A level-3 ("Critical") emergency broadcast floods the entire mesh and bypasses
normal routing rules (spec §9.5). It is the single most abusable message in the
protocol, so the spec requires three co-signers the receiving node trusts above
0.8.

The wire format carried co-signers as bare 32-byte NodeIds, and
`handle_emergency_broadcast` counted them by looking each id up in its trust
graph. Nothing bound those ids to anyone's consent. Any node could list three
NodeIds it did not control — ids that are public, and that any participant in
the mesh has seen — and flood the entire network. The threshold was decorative.

Making it real needed two things the codebase did not have:

1. **A signature per co-signer.** Straightforward, but it changes the wire
   format.
2. **Somewhere to get the co-signer's public key.** The `contacts` table has a
   `public_key` column, but every writer filled it with a placeholder:
   `Vec::new()` from the REST path, and the NodeId itself from the beacon path,
   with the comment "Use node_id as public key placeholder". A NodeId is
   `SHA-256` of the identity key, so it cannot be used to verify anything.

## Decision

### Co-signer entries carry signatures

A co-signer entry becomes `node_id(32) + signature(64)`, 96 bytes:

```rust
pub struct EmergencyCosigner {
    pub node_id: NodeId,
    pub signature: [u8; 64],
}
```

The signed digest is

```
SHA-256( b"mycelium-emergency-cosign-v1:"
       ‖ broadcast_id (16)      // the envelope's message_id
       ‖ originator  (32)
       ‖ level        (1)
       ‖ message_len  (4 LE)
       ‖ message )
```

Every field is load-bearing:

- **`broadcast_id`** stops replay. Without it, an intercepted critical alert
  could be re-flooded under a fresh envelope id indefinitely: the content-only
  digest would still verify, while the receiver's flood-dedup set is keyed on
  the envelope id it no longer matches.
- **`originator`** stops an approval being reused by a different sender.
- **`level`** stops a level-1 approval being promoted to level 3.
- **`message_len`** before `message` stops a length-extension ambiguity between
  two broadcasts whose concatenated fields coincide.

### Verification

`mycelium_crypto::emergency::verify_cosigner` checks, per entry:

1. we hold an identity key for that NodeId — an unverifiable approval is **not**
   an approval, and is not counted;
2. that key hashes to the claimed NodeId, the same binding rule as every other
   ingress path (spec §14.3);
3. the signature verifies over the digest above.

The node then additionally requires trust > 0.8 per co-signer and **three
distinct** valid co-signers, skipping duplicates, before flooding.

Rejection reasons are kept coarse in logs and never sent on the wire: a finer
breakdown would tell a prober which identity keys a node holds.

### Identity keys are recorded where they are already proven

`contacts.public_key` is now populated with the real Ed25519 key at the two
ingress points that have already verified `SHA-256(identity_key) == source`:
`handle_prekey_response` and a successful `handle_session_init`. The beacon path
stores an empty key rather than the NodeId, because a beacon carries no identity
key and a placeholder that looks like a key is worse than none.
`get_contact_identity_key` additionally refuses to return a stored value equal
to the NodeId, so rows written by the old placeholder code can never be
mistaken for keys.

## Consequences

**Easier:**

- The level-3 threshold means what the spec says it means. A flood now requires
  three parties to have actually signed it.
- Contacts carry a verified identity key, which any future feature needing to
  authenticate a peer out of band can use.

**Harder:**

- Breaking wire change: co-signer entries grow from 32 to 96 bytes. The
  protocol is `0.1-draft` with no deployed nodes, so no shim is provided and
  the version field stays `1`. Precedent: ADR-005, ADR-009.
- **Level 3 is now unusable in practice, by design, until collection exists.**
  Nothing in the system gathers three co-signatures: there is no request
  protocol, no approval UI, and `POST /v1/emergency/broadcast` sends an empty
  co-signer list. A level-3 broadcast therefore fails verification at every
  receiver. That is the correct failure direction — unusable beats forgeable —
  but it means this ADR delivers the verification half only. The collection
  half stays on the roadmap.
- A co-signature cannot be verified by a node that has never exchanged keys
  with that co-signer. In a partitioned mesh a legitimate level-3 alert may
  therefore be refused by distant nodes. This is inherent to requiring
  authenticated approval without a key directory, and is the reason the trust
  threshold and the key requirement are checked independently rather than
  conflated.

## Alternatives Considered

1. **Keep bare NodeIds and rely on the trust threshold.** This is what the code
   did. It provides no security at all: the ids are public and unforgeable only
   in the sense that they are not secret.
2. **Have co-signers sign only the message content.** Simpler, and replayable
   forever under new envelope ids. Rejected once the dedup interaction was
   clear.
3. **Fetch the co-signer's key on demand when verifying.** Would avoid storing
   keys, but makes verifying a flood message trigger network traffic — an
   obvious amplification vector on the one message type that already bypasses
   routing limits.
4. **Threshold signatures (one aggregate signature).** Smaller on the wire and a
   better fit conceptually, but it needs a group-key setup the project does not
   have, and it would obscure *which* co-signers approved, which the spec wants
   for accountability (§9.5: emergencies are deliberately non-anonymous).

## Note (2026-11-11)

"the same binding rule as every other ingress path (spec §14.3)" above means
the handlers that §14.3's identity-binding rule actually names: `SessionInit`
and `PrekeyResponse`, which are dropped unless
`NodeId = SHA-256(identity key)`. It is not a property of every handler in
that table — `PrekeyRequest`, for instance, has an empty body and carries no
key to bind — and it is not a claim about transport peer identity. BLE and Wi-Fi Direct exchange a bare NodeId with no key and no proof
of possession (ROADMAP T-34), and the internet transport only began proving it
in ADR-011. Appended rather than edited in place, because these records are
append-only.

## Note (2026-11-12)

The digest above is **superseded by ADR-013**, which this record predates.
Following it as written now produces approvals no receiver will count. What
changed, and why:

- The context string is `b"mycelium-emergency-broadcast-v2:"`, and the digest
  includes `signed_at(8 LE)` between `level` and `message_len`. v1 signatures
  must not be readable as v2 ones, hence the bump.
- `cosign_digest` is now `broadcast_digest`, because the same digest also
  *identifies* the broadcast: flood dedup is keyed on it rather than on the
  envelope's cleartext `message_id`, which any relay can copy.
- "**`broadcast_id`** stops replay" above is too strong. It stops an approval
  being transferred to another alert; it does not stop the same alert being
  re-flooded, because the id is part of what is replayed. `signed_at` and the
  validity window are what bound replay in time.
- A receiver counts three distinct valid co-signatures as before, but at most
  sixteen entries reach the trust and signature checks. Entries it holds no
  identity key for are dismissed by an indexed lookup first, so a padded list
  cannot hide genuine approvals behind it.
- A broadcast is remembered only *after* it has been accepted, and only when
  its envelope destination is `NodeId::ZERO`.

What ADR-013 does not change: the co-signer entry layout
(`node_id(32) + signature(64)`), the verification rules per entry, the trust
threshold, or where identity keys come from.

Appended rather than edited in place, because these records are append-only.

## Note (2026-11-13)

"Rejection reasons are kept coarse in logs" above was not true of the code, and
is now. The handler logged a line per co-signer naming the id and
distinguishing a missing key from insufficient trust from a bad signature —
which is exactly the breakdown this record said it would not disclose, since
together those lines say which identity keys a node holds and whom it trusts.
T-36 made it worse by splitting the key lookup from the trust check for its
verification budget.

Totals by reason were the first attempt at a fix, and they are not one: a
prober listing a single id three times reads its own answer out of the
breakdown — two duplicates, and "unknown key" or "untrusted" for the id it
asked about. Aggregation hides nothing when the attacker chooses the list.

Nor is the *count* safe, which was the second attempt. The verification budget
(ADR-013) is charged only for entries whose key the node holds, so a prober
lists fifteen known-key entries with bad signatures, then the id it is asking
about, then one approval that would count: if the probed key is held, the
budget runs out before that last entry and the count is zero; if it is not,
the count is one. No signature from the probed id is needed.

So a refused critical alert logs that it was refused for too few counted
co-signatures, and no numbers at all.

What this costs: an operator can no longer tell from the log *why* an alert
was refused, or how close it came. They can still answer it locally — the
contacts table says which identity keys they hold, the trust graph says whom
they trust — without the log handing the same answer to whoever is probing.

**What is left, and why it stays.** The budget's ordering is itself observable
to an attacker who can already produce three counting approvals: by padding
with known-key entries it can make the budget run out before its own valid
ones, so whether the alert floods depends on whether this node holds the
padded ids' keys. Charging the budget for *every* entry instead would close
that and reopen something worse — padding with unknown ids would hide genuine
approvals behind it, which is a way to suppress a real alert (T-36's first
review round). Suppressing an alert is worse than telling an attacker who
already holds three trusted signers which keys we have, so the ordering
stands.
