FROM node:20-alpine AS builder

WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci
COPY . .
RUN npm run build

# ── Runtime: serve static files ───────────────────────────────────────────────
FROM node:20-alpine AS runtime

RUN npm install -g serve

# Non-root user
RUN addgroup -S sentinel && adduser -S sentinel -G sentinel
USER sentinel

WORKDIR /app
COPY --from=builder --chown=sentinel:sentinel /app/dist ./dist

EXPOSE 3000

CMD ["serve", "-s", "dist", "-l", "3000"]
