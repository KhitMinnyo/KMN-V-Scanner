# syntax=docker/dockerfile:1

FROM golang:1.23-bookworm AS nuclei-builder
ARG NUCLEI_VERSION=v3.4.10
RUN CGO_ENABLED=0 go install -trimpath -ldflags="-s -w" \
    github.com/projectdiscovery/nuclei/v3/cmd/nuclei@${NUCLEI_VERSION}

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

COPY --from=nuclei-builder /go/bin/nuclei /usr/local/bin/nuclei

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
RUN mkdir -p /app/data

EXPOSE 2025
VOLUME ["/app/data"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "2025"]
