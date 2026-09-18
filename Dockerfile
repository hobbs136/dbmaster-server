# syntax=docker/dockerfile:1
# dbmaster-server — multi-stage build. Pure-Rust deps (sqlx sqlite bundles
# libsqlite3; mysql/postgres drivers + reqwest/rustls are pure Rust) → no
# system DB/TLS libraries needed at build or runtime.
FROM rust:1.95-slim-bookworm AS builder
WORKDIR /app
COPY . .
RUN cargo build --release --bin dbmaster-server

FROM debian:bookworm-slim AS runtime
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --create-home --uid 10001 dbmaster
COPY --from=builder /app/target/release/dbmaster-server /usr/local/bin/dbmaster-server
USER dbmaster
WORKDIR /home/dbmaster
VOLUME ["/home/dbmaster/data"]
ENV SERVER_HOST=0.0.0.0 \
    SERVER_PORT=13400 \
    DATABASE_URL=sqlite:/home/dbmaster/data/dbmaster.db?mode=rwc \
    # CHANGE: #3 — license file MUST live inside the persistent volume, not the
    # container's writable layer. Without this, `docker rm + run` (the standard
    # image-upgrade flow) silently drops the activated license and the server
    # re-lands in Trial/Gated despite the user having paid. Default license_file_path()
    # resolves to ".dbmlicense" relative to CWD (/home/dbmaster) which is NOT in
    # the volume — override here so POST /api/license writes survive upgrades.
    DBMASTER_LICENSE_FILE=/home/dbmaster/data/.dbmlicense
EXPOSE 13400
ENTRYPOINT ["dbmaster-server"]
