FROM node:20-alpine

RUN npm install -g pnpm

WORKDIR /app

# Copy workspace config
COPY package.json pnpm-workspace.yaml pnpm-lock.yaml ./
COPY packages/shared-types/package.json ./packages/shared-types/
COPY apps/api/package.json ./apps/api/
COPY apps/scanner/package.json ./apps/scanner/

# Install all deps
RUN pnpm install --frozen-lockfile

# Copy source
COPY packages/shared-types ./packages/shared-types
COPY apps/api ./apps/api
COPY apps/scanner ./apps/scanner

# Generate Prisma client
RUN cd apps/api && npx prisma generate

WORKDIR /app/apps/api

EXPOSE 4000

CMD ["node", "--loader", "tsx/esm", "src/server.ts"]