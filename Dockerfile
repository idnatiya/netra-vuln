# Central API with the dashboard SPA baked in. TLS is the reverse proxy's job.
FROM node:22.23.1-alpine AS dashboard
RUN corepack enable
WORKDIR /app
COPY dashboard/package.json dashboard/pnpm-lock.yaml dashboard/pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile
COPY dashboard ./
RUN pnpm build

FROM golang:1.26.5-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY core ./core
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/central ./core/cmd/central

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/central /usr/local/bin/central
COPY --from=dashboard /app/dist /srv/dashboard
ENV CENTRAL_DASHBOARD_DIR=/srv/dashboard
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/central"]
CMD ["serve"]
