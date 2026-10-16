# Multi-stage build for the three sesame binaries. Build one with:
#   docker build --build-arg CMD=sesame-broker -t sesame-broker .
# Produces a distroless, non-root, static image. No shell, read-only friendly.
ARG GO_VERSION=1.26
FROM golang:${GO_VERSION}-alpine AS build
ARG CMD
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/app ./cmd/${CMD}

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/app /app
USER nonroot:nonroot
ENTRYPOINT ["/app"]
