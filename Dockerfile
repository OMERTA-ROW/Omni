# syntax=docker/dockerfile:1
# OMNI inbox/worker: receives signed jobs from Jackboy, applies patches,
# runs tests, and reports results back. The runtime image keeps Go and Git
# because the worker runs `go test` and git inside per-job sandboxes.

FROM golang:1.25-bookworm AS build
WORKDIR /src
COPY inbox/go.mod ./
RUN go mod download
COPY inbox/ ./
RUN CGO_ENABLED=0 go build -trimpath -o /out/omni-inbox ./cmd/omni-inbox
RUN CGO_ENABLED=0 go build -trimpath -o /out/omni-link ./cmd/omni-link
RUN CGO_ENABLED=0 go build -trimpath -o /out/omni-shell-exec ./cmd/omni-shell-exec

FROM golang:1.25-bookworm
RUN groupadd --system --gid 10001 omni \
    && useradd --system --create-home --uid 10001 --gid 10001 omni
RUN groupadd --system --gid 10002 omni-sandbox \
    && useradd --system --create-home --uid 10002 --gid 10002 omni-sandbox
WORKDIR /home/omni
COPY --from=build /out/omni-inbox /usr/local/bin/omni-inbox
COPY --from=build /out/omni-link /usr/local/bin/omni-link
COPY --from=build /out/omni-shell-exec /usr/local/bin/omni-shell-exec
COPY docker/entrypoint.sh /usr/local/bin/omni-entrypoint
# Keep the restricted shell executor as the only setuid executable.
RUN chmod 0755 /usr/local/bin/omni-entrypoint \
    && find /usr/bin /usr/sbin /bin /sbin -type f -perm /6000 -exec chmod a-s {} + \
    && chown root:omni /usr/local/bin/omni-shell-exec \
    && chmod 4750 /usr/local/bin/omni-shell-exec
# Starts as root only to prepare $OMNI_LINK_AUDIT_DIR (volume), then drops to uid 10001.
ENV PORT=8080 OMNI_DATA_DIR=/home/omni/omni-data
EXPOSE 8080
# Required env on the host: OMNI_API_KEY, OMNI_CALLBACK_SECRET,
# OMNI_ALLOWED_REPOS. Optional: JACKBOY_CALLBACK_URL, OMNI_GIT_TOKEN.
# Shell execution is opt-in with OMNI_SHELL_ENABLED=true; commands run as omni-sandbox.
# See inbox/README.md for details.
ENTRYPOINT ["omni-entrypoint"]
CMD ["omni-inbox"]
