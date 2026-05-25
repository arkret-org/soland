# syntax=docker/dockerfile:1.7

FROM --platform=$BUILDPLATFORM rust:1-bookworm AS builder

WORKDIR /workspace

COPY --from=contrix-rust-sdk . ./contrix-rust-sdk
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
# tooling). `curl` powers the HEALTHCHECK below; `ca-certificates`
# keeps outbound `https://` (e.g. did:web resolution) working.
RUN apt-get update \
    && apt-get install -y --no-install-recommends tini curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/bin/soland /usr/local/bin/soland

USER 10001:10001
WORKDIR /var/lib/soland

ENV SOLAND_BIND=0.0.0.0:8698
ENV SOLAND_METRICS_BIND=0.0.0.0:9698
ENV SOLAND_OBJECT_STORAGE_BACKEND=local
ENV SOLAND_OBJECT_STORAGE_LOCAL_ROOT=/var/lib/soland/objects
EXPOSE 8698 9698

# P4 (CXP-0007 rollout hygiene) — liveness probe over the public HTTP
# surface. soland mounts `/health` unconditionally (see
# `routing::system::health_router`). The check runs every 30 s with a
# 5 s timeout; allow a 30 s start-up window for diesel migrations.
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD curl -fsS "http://127.0.0.1:8698/health" || exit 1

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/soland"]
