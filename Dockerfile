FROM rust:alpine3.19
ENV RUSTFLAGS="-C target-feature=-crt-static"
RUN apk add musl-dev postgresql-dev
WORKDIR /app
COPY . .
RUN --mount=type=cache,target=/var/cache/buildkit \
    CARGO_HOME=/var/cache/buildkit/cargo \
    CARGO_TARGET_DIR=/var/cache/buildkit/target \
    cargo build --release --locked && \
    cp -v /var/cache/buildkit/target/release/what-the-src /

FROM alpine:3.19
RUN apk add libgcc libpq
WORKDIR /app
COPY --from=0 /what-the-src /
USER nobody
ENV BIND_ADDR=0.0.0.0:8000
ENTRYPOINT ["/what-the-src"]
