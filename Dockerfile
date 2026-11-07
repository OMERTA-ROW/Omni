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

FROM golang:1.25-bookworm
RUN useradd --system --create-home --uid 10001 omni
USER omni
WORKDIR /home/omni
COPY --from=build /out/omni-inbox /usr/local/bin/omni-inbox
COPY --from=build /out/omni-link /usr/local/bin/omni-link
ENV PORT=8080 OMNI_DATA_DIR=/home/omni/omni-data
EXPOSE 8080
# Required env on the host: OMNI_API_KEY, OMNI_CALLBACK_SECRET,
# OMNI_ALLOWED_REPOS. Optional: JACKBOY_CALLBACK_URL, OMNI_GIT_TOKEN.
# See inbox/README.md for details.
CMD ["omni-inbox"]
