# SomeDesk server image. Build from the repository root:
#   podman build -f packaging/server/Dockerfile -t somedesk-server .
FROM docker.io/library/rust:1-slim-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p somedesk-server \
    && strip target/release/somedesk-server

FROM docker.io/library/debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 999 --user-group --home-dir /data --create-home somedesk
COPY --from=build /src/target/release/somedesk-server /usr/local/bin/somedesk-server
USER somedesk
# The TLS certificate (whose fingerprint clients pin) lives here: keep it on a volume.
VOLUME /data
ENV SOMEDESK_DATA_DIR=/data SOMEDESK_LISTEN=0.0.0.0:21116
EXPOSE 21116/udp
ENTRYPOINT ["/usr/local/bin/somedesk-server"]
