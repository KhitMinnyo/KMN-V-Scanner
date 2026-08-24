# syntax=docker/dockerfile:1

# Download the matching Nuclei release binary instead of compiling it. This
# avoids Go toolchain requirements and works for both amd64 and arm64 builds.
FROM alpine:3.21 AS nuclei-downloader
ARG NUCLEI_VERSION=v3.4.10
ARG TARGETARCH
RUN apk add --no-cache ca-certificates curl unzip \
    && NUCLEI_NUMBER="${NUCLEI_VERSION#v}" \
    && NUCLEI_URL="https://github.com/projectdiscovery/nuclei/releases/download/${NUCLEI_VERSION}/nuclei_${NUCLEI_NUMBER}_linux_${TARGETARCH}.zip" \
    && curl --fail --silent --show-error --location "$NUCLEI_URL" --output /tmp/nuclei.zip \
    && unzip -q /tmp/nuclei.zip -d /tmp/nuclei \
    && install -m 0755 /tmp/nuclei/nuclei /usr/local/bin/nuclei

FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    HOST=0.0.0.0 \
    PORT=2025 \
    DATABASE_URL=/app/data/scanner.db

RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap testssl.sh ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=nuclei-downloader /usr/local/bin/nuclei /usr/local/bin/nuclei

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
RUN mkdir -p /app/data

EXPOSE 2025
VOLUME ["/app/data"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "2025"]
