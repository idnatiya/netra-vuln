# Build context: repository root. Bakes the dashboard SPA into the Caddy image.
FROM node:22.23.1-alpine AS dashboard
RUN corepack enable
WORKDIR /app
COPY dashboard/package.json dashboard/pnpm-lock.yaml dashboard/pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile
COPY dashboard ./
RUN pnpm build

FROM caddy:2.10.2-alpine
COPY --from=dashboard /app/dist /srv/dashboard
COPY deploy/central/Caddyfile /etc/caddy/Caddyfile
