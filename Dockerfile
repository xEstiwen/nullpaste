# syntax=docker/dockerfile:1

FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
    -o /out/nullpaste ./cmd/nullpaste \
 && mkdir -p /out/data

# distroless "nonroot" runs as uid 65532 and ships no shell or package manager.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/nullpaste /nullpaste
COPY --from=build --chown=65532:65532 /out/data /data
ENV NULLPASTE_DB_PATH=/data/nullpaste.db
VOLUME /data
EXPOSE 8080
ENTRYPOINT ["/nullpaste"]
CMD ["--addr", ":8080"]
