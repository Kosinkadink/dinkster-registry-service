# Signed release notices

`dinkster_registry_service.security` defines signed release notices and trust
updates. A signature authenticates registry statements; it neither proves that
an artifact is safe nor undoes previous execution. Expiry is metadata for an
explicit client freshness policy, never a lift or an automatic default stop.

## Envelope and signatures

An envelope contains exactly `signed` and `signatures`. Each signature has a
`keyId` (`sha256:` of its raw 32-byte Ed25519 public key) and `signature`
(canonical padded standard base64 of the 64 signature bytes). Ed25519 signs the
`signed` object serialized as ASCII JSON with sorted object keys, no whitespace,
ASCII escapes and no NaN/infinity. Arrays retain their order. JSON fields are
camelCase; duplicate and unknown fields are rejected. Integers are not booleans
or floats. Times are ISO-8601 strings with an explicit timezone.

The signer uses model JSON serialization before canonicalization. Verifiers
canonicalize the received `signed` object, not a reconstructed object with
defaults. At least one signature must verify with an independently trusted key.
The signature covers the format and registry as well as every notice field.

## Release document

`signed.format` is `dinkster.security/1`. Other fields are `registry` (the exact
independently trusted registry identifier), positive increasing `revision`,
`issuedAt`, `expiresAt`, `notices` and `ownershipChanges`. Each notice contains:

- `id`: stable UUID; `revision`; `previousRevision` (null for a new notice).
- `release`: `pack`, `version`, `artifactDigest` (`blake3:` or `sha256:`).
- `state`: `malicious`, `vulnerable` or `affected`; `status`: `active` or `cleared`.
- `actor`, `authority` (`security` or `publisher`), `securityConfirmed`.
- `changedAt`, `reason`, `message`, `incident`.
- `fixedRelease`: another exact release of that pack, or null;
  `fixedLockDigest`: a digest or null. These are suggestions, not installation
  approval or compatibility proof.
- `causes`: distinct malicious dependency digests, required for `affected` and
  empty for the other states. The consumer is affected, not itself malicious.

Documents retain current cleared notices. Absence never clears a cached notice.
Updates preserve notice IDs and exact release identities; replacements increase
the notice revision and name the previous revision. Clients can skip revisions
but cannot accept an older revision or changed bytes at the same revision.
Keep the last accepted document atomically with the client's revision state.
Changing a decision or learning a lift does not implicitly resume jobs or
install software. Registry role checks, not a publisher-provided field, decide
who can create or clear a classification.

`ownershipChanges` contains immutable signed `ownership_transferred` records:
`id` (the shared audit event ID), `revision`, `packId` (unchanged by transfer),
`pack`, `previousPublisher`, `publisher`, `actor`, `changedAt` and `reason`.
Transfers and returns append new records; they never rewrite published files
or delete a previous ownership record. These notices announce the registry's
audited ownership transaction, not a second way to perform a transfer.

## Independent trust and rotation

`SecurityTrust` is provisioned independently, not copied from the notice feed.
Its format is `dinkster.security-trust/1`, with the same registry/revision/time
fields and a nonempty `keys` array (`keyId`, base64 raw `publicKey`).
`verify_security_trust` accepts a higher revision only when a current trusted
key signs it. The accepted key set replaces the previous key set. A new key
cannot authorize itself, and a release document cannot change trust.

For loss or compromise of every currently trusted key, an administrator must
independently authenticate replacement public-key bytes through the original
trusted provisioning channel. Install that trust explicitly; do not reset or
delete the cached release document, notice decisions or revision checkpoint.
The next notice verification still checks the previous document. Never accept
an unauthenticated feed's proposed key as recovery. No production signing key
or signing credential is distributed in this repository.

## Registry authority and reports

Security authority is an explicit, revocable role, separate from publisher
membership and registry operation. An operator assigns or removes that role
with `PUT /v1/security/roles/{user}` and `{enabled, reason}`. The bearer must be
unscoped. Role changes preserve the actor, reason and time in the audit log.

`POST /v1/security/notices` accepts `operation`, `release`, `expectedRevision`,
`state`, `reason`, `message`, `incident`, optional `fixedRelease`,
`fixedLockDigest` and `causes`. A first report expects revision zero; subsequent
changes name the current notice revision. Operations are `issue`, `confirm`,
`correct`, `lift` and `withdraw`. The service derives issuer and authority from
the authenticated actor, not the submitted JSON. Only an exact catalog release
identity is accepted. A publisher may immediately issue a vulnerability or
malicious report for its own release; only the original reporter may withdraw
an unconfirmed vulnerability. Security confirmation or correction prevents
publisher withdrawal. Only the security role may lift a malicious report or
confirm, correct or lift a classification. An operator without that role has
no classification authority. Security actions require an unscoped token.

`GET /v1/security/notices/history` returns the append-only notice history to an
authenticated caller. Each change keeps the notice identity and previous
revision. The signing producer retains the latest notice, including cleared
notices. These administration responses are not the signed public feed; static
publication and mirror delivery are separate from the mutation interfaces.

## Upload controls

`PUT /v1/security/uploads` accepts `subjectType` (`pack` or `publisher`),
`subject`, `stopped` and `reason`. Security responders can stop or resume either
scope; publishers can control their own packs only. A security stop cannot be
downgraded by repeating a publisher stop, and only security can resume it.
An explicit security resume can override a publisher stop. A publisher-wide
stop covers existing packs and new submissions under that publisher; a pack
resume does not override a publisher-wide stop. All changes append actor,
authority, reason, time and revision to the existing audit event store.

Submission, promotion preparation and final activation check the same controls
under the transaction lock used to change them. A stopped prepared promotion
keeps its quarantine bytes and pending outbox work for retry; it cannot activate
until uploads resume. No control mutates already published release files or
classifications. PostgreSQL uses a transaction advisory lock; SQLite uses an
immediate write transaction. Durable security revisions, not UUID ordering or
wall-clock order, determine which record replaces another. No database schema
conversion or compatibility path is involved.
