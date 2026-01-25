FROM rust:alpine3.23
ENV RUSTFLAGS="-C target-feature=-crt-static"
RUN apk add ca-certificates musl-dev postgresql-dev xz-dev zstd-dev
WORKDIR /app
COPY . .
RUN --mount=type=cache,target=/var/cache/buildkit \
    CARGO_HOME=/var/cache/buildkit/cargo \
    CARGO_TARGET_DIR=/var/cache/buildkit/target \
    cargo build --release --locked && \
    cp -v /var/cache/buildkit/target/release/what-the-src /

FROM alpine:3.23
RUN apk add ca-certificates libgcc libpq xz-libs zstd-libs git
# current rpm parser depends on /usr/bin/bsdtar
RUN apk add libarchive-tools
WORKDIR /app
COPY --from=0 /what-the-src /
USER nobody
ENV BIND_ADDR=0.0.0.0:8000
ENV WHATSRC_FS_TMP=/var/cache/whatsrc
ENTRYPOINT ["/what-the-src"]
