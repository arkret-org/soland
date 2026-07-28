# Regression Review

## 2026-07-28 — standard recovery receipt write was not actually retry-safe

- Surface: `POST /_arkret/root/identity/recovery-receipt`.
- Regression: the registered operation declares object-id idempotency and byte-identical retry
  safety, but both memory and persistent receipt paths reject an already-seen receipt/session
  instead of returning the first accepted outcome for identical canonical bytes.
- Detection: operation-registry, handler, and storage-port cross-check during recovery closure
  review.
- Status: obsolete standalone protocol route removed. The replacement must live only in
  `RecoveryTransaction.issue_terminal_receipt`; durable transaction storage remains blocked on the
  recovery transaction closure reports.
- Required correction: persist canonical request digest plus first outcome and atomically implement
  the three-way same-id/same-bytes, same-id/different-bytes, and same-session/different-id matrix.
- Prevention dimension: `retry_safe=true` must have response-lost and concurrent duplicate tests at
  the storage boundary, not only a successful handler test.

## 2026-07-28 — receipt schema algorithms exceeded the executable verifier

- Surface: recovery receipt schema validation and device signature verification.
- Regression: validation admits `ES256` and `ML-DSA-65`, while authorized recovery-device key
  projection and the verifier always decode Ed25519 and require a 64-byte Ed25519 signature.
- Detection: schema/model/verifier cross-check.
- Required correction: restrict the v1 receipt wire algorithm to `Ed25519` until device
  authorization, key projection, possession proof, Event verification, receipt verification, and
  KATs all support another algorithm as one closed stack.
- Prevention dimension: adding an algorithm token to a schema must be gated by an end-to-end
  executable algorithm capability, not parser acceptance alone.
- Status: fixed in the current spec and SDK receipt DTO; the standalone Soland receipt verifier was
  removed with its noncanonical route.
