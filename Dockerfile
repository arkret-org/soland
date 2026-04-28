# syntax=docker/dockerfile:1.7

FROM --platform=$BUILDPLATFORM rust:1-bookworm AS builder

WORKDIR /workspace

COPY --from=contrix-rust-sdk . ./contrix-rust-sdk
COPY . ./serverx

WORKDIR /workspace/serverx

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/workspace/serverx/target \
    cargo build --locked --release && \
    cp target/release/serverx /usr/local/bin/serverx

FROM debian:bookworm-slim AS runtime

COPY --from=builder /usr/local/bin/serverx /usr/local/bin/serverx

USER 10001:10001
WORKDIR /var/lib/serverx

ENV SERVERX_BIND=0.0.0.0:8787
EXPOSE 8787

ENTRYPOINT ["/usr/local/bin/serverx"]
