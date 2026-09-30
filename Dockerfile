# Synthetic development only: the host can still administer Docker and is not a
# production credential-isolation boundary. Matches package-lock Playwright.
FROM mcr.microsoft.com/playwright:v1.63.0-noble AS development

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts
COPY . .
RUN npm run build

ENV NODE_ENV=production \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    HOME=/tmp/boring-login \
    BROKER_CONFIG=/app/.local/broker.json \
    BROKER_HOST=127.0.0.1

# Compose uses the host's non-root UID/GID so the private mounted settings remain
# mode 0600 and can be atomically updated without granting world/group access.
USER pwuser
CMD ["node", "docker/entrypoint.mjs"]

FROM development AS runtime
USER root
RUN npm prune --omit=dev --ignore-scripts
USER pwuser
