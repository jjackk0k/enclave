# The Cedar PDP as a deployable service image. Build context = repo root.
FROM node:22-alpine
WORKDIR /app
# deps first (cedar-wasm) for layer caching
COPY poc/enforcement-seam/package.json ./
RUN npm install --omit=dev --no-audit --no-fund
# service code + policies
COPY poc/enforcement-seam/pdp-server.mjs poc/enforcement-seam/policy-engine.mjs ./
COPY poc/enforcement-seam/policy ./policy
ENV PDP_HOST=0.0.0.0 PDP_PORT=8990 NODE_NO_WARNINGS=1
EXPOSE 8990
USER node
CMD ["node", "--experimental-wasm-modules", "pdp-server.mjs"]
