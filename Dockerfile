# Multi-stage build: Node builds the console, the runtime is Python's standard library only.
FROM node:24-slim AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
RUN npm run build

FROM python:3.12-slim
RUN groupadd --gid 10001 zyvor && useradd --uid 10001 --gid 10001 --no-create-home zyvor && mkdir /data && chown 10001:10001 /data
WORKDIR /app
COPY duvora /app/duvora
COPY --from=web /src/duvora/static /app/duvora/static
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 DUVORA_DB=/data/dpu.db
USER 10001:10001
EXPOSE 8787
HEALTHCHECK --interval=30s --timeout=5s CMD ["python", "-m", "duvora.healthcheck"]
ENTRYPOINT ["python", "-m", "duvora.server", "--host", "0.0.0.0"]
