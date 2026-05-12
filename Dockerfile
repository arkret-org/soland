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

COPY --from=builder /usr/local/bin/soland /usr/local/bin/soland

USER 10001:10001
WORKDIR /var/lib/soland

ENV SOLAND_BIND=0.0.0.0:8698
ENV SOLAND_OBJECT_STORAGE_BACKEND=local
ENV SOLAND_OBJECT_STORAGE_LOCAL_ROOT=/var/lib/soland/objects
EXPOSE 8698

ENTRYPOINT ["/usr/local/bin/soland"]
