# Build context: repository root.
FROM golang:1.26.5-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY central ./central
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/central ./central/cmd/central

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/central /usr/local/bin/central
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/central"]
CMD ["serve"]
