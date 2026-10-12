# Readdit site (Nuxt). Used by `docker compose --profile full up`.
FROM node:24-slim AS build
WORKDIR /app
COPY . .
RUN npm install --no-audit --no-fund && npm run build

FROM node:24-slim
WORKDIR /app
COPY --from=build /app/.output ./.output
ENV NODE_ENV=production HOST=0.0.0.0 PORT=3000
EXPOSE 3000
CMD ["node", ".output/server/index.mjs"]
