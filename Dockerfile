# syntax=docker/dockerfile:1.7

FROM --platform=$BUILDPLATFORM rust:1-bookworm AS builder

WORKDIR /workspace

COPY --from=arkret-rust-sdk . ./arkret-rust-sdk
COPY --from=arkret-spec . ./arkret-spec
COPY . ./soland

WORKDIR /workspace/soland

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/workspace/soland/target \
    cargo build --locked --release && \
    cp target/release/soland /usr/local/bin/soland

FROM debian:bookworm-slim AS runtime

# `tini` provides a minimal PID-1 init so soland's tokio runtime sees
# SIGTERM/SIGINT cleanly and child reaping works (the bare Rust binary
# would otherwise need to handle signal forwarding for any subprocess
# tooling). `ca-certificates` keeps outbound `https://` (e.g. did:web
# resolution) working. We dropped the `curl` runtime dependency in P5
# (5.5) — the HEALTHCHECK now invokes the bundled `soland healthcheck`
# subcommand, which keeps the image distroless-compatible.
RUN apt-get update \
    && apt-get install -y --no-install-recommends tini ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/bin/soland /usr/local/bin/soland

USER 10001:10001
WORKDIR /var/lib/soland

ENV SOLAND_BIND=0.0.0.0:8698
ENV SOLAND_METRICS_BIND=0.0.0.0:9698
ENV SOLAND_OBJECT_STORAGE_BACKEND=local
ENV SOLAND_OBJECT_STORAGE_LOCAL_ROOT=/var/lib/soland/objects
EXPOSE 8698 9698

# P5 (5.5) — liveness probe via the bundled `soland healthcheck`
# subcommand. The probe reads `SOLAND_BIND` (or `SOLAND_HEALTHCHECK_URL`)
# and HTTPs `/health`. Eliminates the runtime `curl` dependency that
# previously blocked migrating this image to a distroless base.
# `--start-period` covers the diesel migration window on first boot.
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD ["/usr/local/bin/soland", "healthcheck"]

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/soland"]
