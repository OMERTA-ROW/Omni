FROM golang:1.25-bookworm AS supervisor-build
WORKDIR /src
COPY sandbox/supervisor/main.go ./main.go
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/omni-sandbox-supervisor ./main.go

FROM node:22-bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends bubblewrap passwd util-linux \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --gid 65534 --no-create-home omni-sandbox
WORKDIR /app
COPY sandbox/server.mjs sandbox/server.test.mjs sandbox/containment.test.mjs ./
COPY --from=supervisor-build /out/omni-sandbox-supervisor /usr/local/bin/omni-sandbox-supervisor
RUN mkdir -p /data && chown 10001:65534 /data && chmod 0700 /data
ENV PORT=8080 \
    OMNI_SANDBOX_ENABLED=false \
    OMNI_SANDBOX_DATA_DIR=/data
USER 10001:65534
VOLUME ["/data"]
EXPOSE 8080
ENTRYPOINT ["/usr/bin/flock", "--no-fork", "-n", "/data/service.lock", "node", "/app/server.mjs"]
