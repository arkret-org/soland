# Typed `#[endpoint]` migration plan

> Reference: palpo (`E:\Works\palpo-im\palpo`). The first refactor pass (this
> branch) only renamed `#[handler]` → `#[endpoint]`; every handler still has a
> raw `(req, depot, res)` signature, so the salvo-oapi macro has nothing to
> reflect on and the generated OpenAPI document carries empty operations.
> This file plans the real conversion.

## Why this matters

`#[endpoint]` only produces useful OpenAPI when each handler exposes:

1. **Typed extractors** — `JsonBody<T>`, `QueryParam<T, REQUIRED>`, `PathParam<T>`, plus `T: ToParameters` for header/query bundles. The macro picks these up via `EndpointArgRegister` and emits `parameters[]` + `requestBody`.
2. **Typed return** — `Result<Json<T>, AppError>` where both arms implement `EndpointOutRegister`. The macro emits `responses[200]` from `T: ToSchema` and `responses[4xx/5xx]` from `AppError`.

palpo's pattern is the production-ready template. The job is to mirror it for soland's ~180 endpoints.

## Scale baseline (2026-05-06)

| Surface | Count |
| --- | --- |
| `#[endpoint]` handlers in `src/routing/*.rs` | 180 |
| `pub struct` types in `src/wire.rs` | 151 (none currently `ToSchema`) |
| Wire types already `ToSchema` in contrix-sdk (`cfg_attr(feature = "salvo", derive(ToSchema))`) | 261+ across `core/{model,sync,service,cursor}.rs` |

## Foundation tasks (Phase A) — ✅ landed

| # | Task | Status | Notes |
| --- | --- | --- | --- |
| A-1 | `soland::routing::extract::AuthArgs` (`#[derive(ToParameters)]` with `Authorization` header field) | ✅ | [src/routing/extract.rs](src/routing/extract.rs); call `aa.authenticated_session(state, req)?`. |
| A-2 | `error::AppError` enum + `impl Writer` + `impl EndpointOutRegister` (400/401/403/404/409/429/500) | ✅ | [src/error.rs](src/error.rs); response body schema is `contrix_sdk::ErrorEnvelope`. |
| A-3 | `JsonResult<T>` / `EmptyResult` aliases + `json_ok` / `empty_ok` helpers | ✅ | [src/result.rs](src/result.rs); re-exported from crate root. |
| A-4 | `#[derive(salvo::oapi::ToSchema)]` on every wire.rs struct (151 types) | ✅ | [src/wire.rs](src/wire.rs); unconditional derive — soland always builds with `salvo`. |
| A-5 | `EmptyResponse` marker type | ✅ | [src/result.rs](src/result.rs). |
| A-6 | `salvo::prelude::Json<T>` Writer + ToSchema | ✅ (verify-only) | salvo 0.93 already supports it. |
| A-7 | contrix-sdk re-exported types are `ToSchema` | ✅ | confirmed via build. |

**SDK changes landed:**

| # | Change |
| --- | --- |
| SDK-1 | `contrix_sdk::SpaceSearchEntry` got `#[cfg_attr(feature = "salvo", derive(ToSchema))]` ([contrix-rust-sdk/crates/sdk/src/search.rs](../contrix-rust-sdk/crates/sdk/src/search.rs:11)). |
| SDK-2 | Added `salvo` (optional, `oapi`) and `contrix-core/salvo` to the `salvo` feature of the `contrix` crate ([contrix-rust-sdk/crates/sdk/Cargo.toml](../contrix-rust-sdk/crates/sdk/Cargo.toml)). |
| SDK-3 | (Deferred) — re-exporting `JsonBody/QueryParam/PathParam` from `contrix_sdk::salvo_adapter::extract` is sugar; not required for the conversion. |

## Per-domain conversion (Phase B..L)

> Each row is a self-contained PR. After Phase A lands, these ten can run in parallel. Within a row, every endpoint follows the same shape: `JsonBody<RequestT>` (POST/PUT) or `QueryParam<T, REQ>` / `PathParam<T>` (GET/DELETE), `aa: AuthArgs` for protected routes, `JsonResult<ResponseT>` return, replace inner `auth_or_render(...)` / `req.parse_json::<T>().await?` / `query_param(req, "x")` calls with the typed extractors.

| Phase | Domain | Endpoints | Files | Status |
| --- | --- | --- | --- | --- |
| B | describe (introspection — easiest) | 8 | `src/routing/describe.rs` | ✅ landed |
| C | auth + account + device-pairing | 10 | `src/routing/{auth,account,device}.rs` | ✅ landed (3+5+2) |
| D | space + message + reaction + read_marker | 12 | `src/routing/{space,message,reaction,read_marker}.rs` | ✅ landed (5+3+2+2) |
| E | entity + relation + view + schema | 16 | `src/routing/{entity,relation,view,schema}.rs` | pending |
| F | sync + events + repo | 23 | `src/routing/{sync,events,repo}.rs` | pending |
| G | directory + identity + index | 23 | `src/routing/{directory,identity,index}.rs` | pending |
| H | authz + policy + admin + audit | 13 | `src/routing/{authz,policy,admin,audit}.rs` | pending |
| I | keys + key_backup_restore | 34 | `src/routing/{keys,key_backup_restore}.rs` | pending |
| J | push + push_outbound + profile | 14 | `src/routing/{push,push_outbound,profile}.rs` | pending |
| K | federation + mimi + webrtc + blob + moderation + device_messages | 24 | `src/routing/{federation,mimi,webrtc,blob,moderation,device_messages}.rs` | pending |
| L | recovery + remaining mod.rs/lib.rs handlers | 6 | `src/routing/recovery.rs`, `src/routing/mod.rs`, `src/lib.rs` | pending |

**Progress:** 30 / 183 endpoints converted (B + C + D). The remaining seven
phases follow the same template; pick them up in the order listed above.

### Phase C/D recipe notes

Patterns that came out of the first three phases — useful when picking up
E..L:

- `JsonBody<T>` is the common request extractor. Every wire request type now
  derives `ToSchema`, so `JsonBody<RequestT>` works without further changes.
- `PathParam<String>` for `{space_id}` / `{member_did}` style segments. Use
  multiple `PathParam<String>` arguments when the route has multiple
  placeholders — the macro picks them up positionally by name.
- `QueryParam<T, REQUIRED>` for query strings; `QueryParam<String, false>`
  with `.into_inner()` mirrors the legacy `query_param(req, "x")` flow.
- Error returns: prefer the convenience constructors on `AppError`
  (`AppError::not_found(...)`, `::invalid_param(...)`, `::capability_denied(...)`).
  Otherwise `AppError::new(ErrorCode::Conflict, msg).with_status(StatusCode::CONFLICT)`
  to override the registry-default status.
- Helpers that previously rendered directly into `Response` (e.g.
  `render_space_lifecycle`) need a `Result<T, AppError>` twin — see
  `space::space_lifecycle_response` for the pattern.
- Tests: every per-domain PR should extend `tests/openapi_typed.rs` with the
  new request/response type names so the OpenAPI doc keeps proving its
  schemas are real, not synthetic placeholders.

### Verification (B + C + D)

`cargo test --test openapi_typed` asserts the OpenAPI doc carries:

- Every typed-only operationId from B (`cx.auth.bridge.describe`,
  `cx.authz.describe`, `cx.policies.describe`, `cx.device_messages.describe`,
  `cx.keys.backups.describe`, `cx.integration.describe`).
- 13 typed request body schemas from C/D (`DevLoginRequest`,
  `SessionGrantExchangeRequest`, `RegisterAccountRequest`,
  `ContactRequestRequest`, `ContactRespondRequest`, `SendMessageRequest`,
  `ReviseMessageRequest`, `RedactMessageRequest`, `AddReactionRequest`,
  `RemoveReactionRequest`, `SetReadMarkerRequest`, `CreateSpaceRequest`,
  `AddSpaceMemberRequest`).
- 11 typed response shapes from C/D (`DevLoginResponse`, `LogoutResponse`,
  `AccountResponse`, `ContactResponse`, `ContactsResponse`,
  `SendMessageResponse`, `ReviseMessageResponse`, `RedactMessageResponse`,
  `ReactionResponse`, `ReadMarkerResponse`, `SpaceLifecycleResponse`).
- Three describe-typed responses (`HealthResponse`, `IntegrationDescribeResponse`,
  `AuthBridgeDescribeResponse`) and the shared `ErrorEnvelope`.

> **`SOLAND_EXTENSION_OPERATIONS` co-existence**: `add_contract_operation` in
> [src/lib.rs](src/lib.rs) now skips entries whose (path, method) is already
> populated by a typed `#[endpoint]`. This lets typed and untyped endpoints
> share the same OpenAPI doc during the per-domain rollout — once every
> phase lands, delete the table in Phase M-1.

## Cleanup (Phase M — once every per-domain phase lands)

| # | Task | Files |
| --- | --- | --- |
| M-1 | Delete the `SOLAND_EXTENSION_OPERATIONS` table from `src/lib.rs`. Every operation_id, summary, request body, and response body now comes from `#[endpoint]` annotations. The OpenAPI test in `tests/http_api.rs` should now pass against `merge_router(&router)` alone. | `src/lib.rs`, `tests/http_api.rs` |
| M-2 | Delete `register_soland_specific_schemas` once `FacetName / ViewRenderer / FacetConstraint / IndexQueryRequest` are typed in `src/wire.rs` and reachable from `index_query`'s `JsonBody<IndexQueryRequest>`. | `src/lib.rs`, `src/wire.rs` |
| M-3 | Drop `crate::routing::util::{render_error, query_param, query_flag, query_list, bearer_token}` once every callsite has been replaced by typed extractors / `AppError::from_error_code(...)?`. | `src/routing/util.rs` |
| M-4 | Drop the `auth_or_render` / `authenticated_session` raw helpers in `src/routing/auth.rs` in favor of the new `AuthArgs` extractor. | `src/routing/auth.rs` |
| M-5 | Update `_todos.md` Q1 to "completed" and remove the `#[endpoint]` typed-extractor item from the open list. | `_todos.md` |
| M-6 | Add a positive OpenAPI test that asserts `paths."/api/v1/messages/send".post.requestBody.content."application/json".schema.$ref == "#/components/schemas/SendMessageRequest"` (and similar for representative routes) — locks in that real schemas are wired, not synthetic placeholders. | `tests/http_api.rs` |

## Per-endpoint template

```rust
// before
#[endpoint]
pub async fn send_message(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else { return; };
    let body: SendMessageRequest = match req.parse_json().await {
        Ok(body) => body,
        Err(_) => { render_error(res, BAD_REQUEST, "bad_json", "invalid send"); return; }
    };
    // … 50 lines of validation + state writes …
    res.render(Json(SendMessageResponse { … }));
}

// after
#[endpoint(
    operation_id = "cx.messages.send",
    tags("messages"),
    summary = "Send a message to a Space",
)]
pub async fn send_message(
    aa: AuthArgs,
    depot: &mut Depot,
    body: JsonBody<SendMessageRequest>,
) -> JsonResult<SendMessageResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state)?;
    let body = body.into_inner();
    // … same validation + state writes, but using `?` against AppError …
    json_ok(SendMessageResponse { … })
}
```

Each conversion adds:

- A guaranteed `requestBody` ref to the wire type.
- A guaranteed `responses[200]` ref to the wire type.
- The four canonical 4xx/5xx responses from `AppError::EndpointOutRegister`.
- A spec-aligned `operation_id` string surfaced in tooling.

## Risk register

| Risk | Mitigation |
| --- | --- |
| `#[derive(ToSchema)]` on a wire type fails because of a custom `Deserialize` (e.g. an enum with `serde(untagged)`). | Implement `ToSchema` manually using `Object::with_type(BasicType::Object)` — palpo does this for `LoginType` and `ErrorKind`. |
| `JsonBody<T>` rejects a body the existing `req.parse_json::<T>().await.unwrap_or_default()` callsite previously tolerated. | Per palpo: `body.into_inner()` first, then if `body.is_default()` re-parse the raw payload via `req.payload().await`. Same fallback pattern works for soland. |
| Auth flow uses both bearer tokens **and** federation HTTP-message-signature. The single `AuthArgs` doesn't capture both. | Two extractors: `AuthArgs` (bearer) and `FederationAuthArgs` (signature header bundle). Each handler pulls whichever is appropriate. |
| Generated OpenAPI bloats from Schema duplication when the same wire type appears in many endpoints. | salvo-oapi already deduplicates by component name. The salvo_adapter `install_contrix_oapi_namer()` short-mode keeps names compact. |
| `tests/http_api.rs::contrix_openapi_spec_contains_facet_projection_contracts` may fail mid-migration because `SOLAND_EXTENSION_OPERATIONS` and the new typed entries collide on the same path. | Keep `SOLAND_EXTENSION_OPERATIONS` in `lib.rs` until **every** route in the test list has been converted. Delete it in Phase M-1 only. |

## Schedule (rough)

| Sprint | Phases | Notes |
| --- | --- | --- |
| Sprint 1 | A (+ optional SDK-3) | One engineer, ~2 days. Trial-convert one handler in describe.rs to validate the template before mass updates. |
| Sprint 2 | B + C + D + E in parallel | Four engineers, ~1 day each. |
| Sprint 3 | F + G + H + I + J + K + L | Six engineers, ~1-2 days. I (key_backup_restore) is the heaviest. |
| Sprint 4 | M cleanup | One engineer, half a day. |

A single-engineer track could complete the migration in ~2 working weeks once Phase A lands.

## What this plan does NOT cover

- Per-handler **`instrument(span)`** observability — `_todos.md` Q5 stays separate.
- **Federation HTTP-message-signature** transcript verification — `_todos.md` C1.
- **Streaming response** types (e.g. `sync_subscribe`'s SSE) — they need a custom `Writer`/`EndpointOutRegister` impl rather than `Json<T>`. Note in the per-domain rows when encountered.
- The dev-only `dev_login` and `admin/{resource}` routes — they get converted too, but ship behind a `dev` Cargo feature per `_todos.md` Sec-2.
