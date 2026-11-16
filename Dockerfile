# OSINT MCP — self-contained server image (stdio transport)
FROM python:3.12-slim

# Chromium for the browser/deep-research tools
RUN apt-get update \
    && apt-get install -y --no-install-recommends chromium ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY osint_mcp ./osint_mcp
COPY server.py run.sh keys.example.json ./

RUN pip install --no-cache-dir .

# Runtime defaults; mount or pass your own values
ENV OSINT_HEADLESS=1 \
    OSINT_BROWSER_PATH=/usr/bin/chromium \
    OSINT_SHOTS_DIR=/tmp/osint-shots \
    OSINT_LOG_LEVEL=WARNING \
    PYTHONUNBUFFERED=1

# Non-root user; case DB lives in the mounted volume if provided
RUN useradd --create-home --shell /usr/sbin/nologin osint \
    && mkdir -p /home/osint/.local/share/osint-mcp /tmp/osint-shots \
    && chown -R osint:osint /home/osint /tmp/osint-shots
USER osint

# Windows/macOS/mac container users: mount a volume for the case database:
#   -v osint-cases:/home/osint/.local/share/osint-mcp
VOLUME ["/home/osint/.local/share/osint-mcp"]

# MCP over stdio
ENTRYPOINT ["python", "server.py"]
