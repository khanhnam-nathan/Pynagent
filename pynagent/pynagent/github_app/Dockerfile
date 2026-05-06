# Dockerfile for PyNEAT GitHub App
# Builds a production Docker image of the Probot-based GitHub App

FROM node:18-slim AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Copy package files
COPY package*.json ./
COPY .env.example /app/.env.docker

# Install Node.js dependencies
RUN npm ci --only=production && npm cache clean --force

# Python dependencies for pyneat-wrapper
RUN pip3 install --no-cache-dir pyneat-cli

# ---------------------------------------------------------------------------
# Production image
# ---------------------------------------------------------------------------

FROM node:18-slim AS production

# Security: run as non-root user
RUN groupadd -r appgroup && useradd -r -g appgroup appuser

WORKDIR /app

# Copy Node.js dependencies from builder
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /usr/local/bin/node_modules/.bin ./node_modules/.bin
COPY --from=builder /usr/local/lib/node_modules ./node_modules/node_modules
COPY package*.json ./
COPY .env.docker /app/.env.example

# Copy application code
COPY . .

# Ensure non-root user owns the app directory
RUN chown -R appuser:appgroup /app

# Switch to non-root user
USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:3000/health || exit 1

EXPOSE 3000

ENV NODE_ENV=production
ENV PORT=3000

CMD ["node", "index.js"]
