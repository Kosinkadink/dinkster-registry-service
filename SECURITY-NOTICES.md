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
