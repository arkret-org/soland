# Soland improvement tasks

## Analysis summary

- The project already includes GitHub workflows for CI, audit, Docker image build, multisig drill, release, and typos checks under `.github/workflows`.
- Database tables now use plural names for the renamed surfaces: `account_datas` and `audit_logs`.
- Blob metadata is separated from object bytes: the `blobs` table stores `storage_backend`, `storage_key`, and `size_bytes`, while bytes live behind the object-storage abstraction.
- Database schema and Rust type definitions have drift in several places due to ongoing changes; any schema rename must update Diesel schema, SQL queries, state records, tests, and documentation together.
- Source structure is mostly coherent by domain (`routing`, `persistence`, `state`, `reducer`), but object/file storage is missing a first-class module and should not live inside HTTP handlers.
- Migrations should be squashed for this breaking release: keep the final schema in one migration folder and remove compatibility migrations for old table/column names.

## Implementation checklist

- [x] Inventory current database tables, blob path usage, config, CI, Docker, and typos setup.
- [x] Rename legacy singular account/audit database tables to plural final table names.
- [x] Update Diesel schema, SQL queries, persistence store code, audit route code, docs, and migration rollback files for the table renames.
- [x] Introduce a storage abstraction module for user-uploaded objects with local filesystem and S3-compatible backends.
- [x] Move blob upload/download byte IO out of `routing::blob` and into the storage abstraction.
- [x] Update `AppConfig`, `.env.example`, README, deployment docs, and Docker defaults for local/S3-compatible object storage configuration.
- [x] Remove database BYTEA blob body storage from the primary schema and track blob `storage_backend`, `storage_key`, and `size_bytes`.
- [x] Update blob quota calculations and tests to use metadata `size_bytes` instead of in-memory byte length.
- [x] Squash migrations into one final schema migration folder.
- [x] Remove obsolete database scaffolds and compatibility schema entries from Diesel schema and migrations.
- [x] Run `cargo fmt`, `cargo check --locked`, `typos`, and the local object-storage round-trip test.
- [ ] Resolve pre-existing full-test blockers: `error::tests::{variant_count_matches_registry, wire_codes_round_trip}`, `reducer::lattice_kinds::tests::event_kind_mappings_count_is_at_least_membership_consent_lifecycle`, and the push-notify assertion inside `auth_keys_device_messages_and_blobs_work`.
