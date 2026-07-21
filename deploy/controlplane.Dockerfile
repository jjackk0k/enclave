# The egress broker + a stand-in upstream, as deployable services (dep-free node).
# One image, run twice with different CMDs from compose. Build context = repo root.
FROM node:22-alpine
WORKDIR /app
COPY poc/full-stack/broker-server.mjs poc/full-stack/upstream-mock.mjs ./
ENV NODE_NO_WARNINGS=1
USER node
# default CMD overridden per-service in docker-compose.yml
CMD ["node", "broker-server.mjs"]
