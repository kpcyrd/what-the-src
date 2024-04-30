FROM rust:alpine3.19
ENV RUSTFLAGS="-C target-feature=-crt-static"
RUN apk add musl-dev postgresql-dev bzip2-dev xz-dev zstd-dev
WORKDIR /app
COPY . .
RUN --mount=type=cache,target=/var/cache/buildkit \
    CARGO_HOME=/var/cache/buildkit/cargo \
    CARGO_TARGET_DIR=/var/cache/buildkit/target \
    cargo build --release --locked && \
    cp -v /var/cache/buildkit/target/release/what-the-src /

FROM alpine:3.19
RUN apk add libgcc libpq libbz2 xz-libs zstd-libs git
# current rpm parser depends on /usr/bin/bsdtar
RUN apk add libarchive-tools
WORKDIR /app
COPY --from=0 /what-the-src /
USER nobody
ENV BIND_ADDR=0.0.0.0:8000
ENV WHATSRC_GIT_TMP=/var/cache/whatsrc
ENTRYPOINT ["/what-the-src"]
