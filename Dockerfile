FROM python:3.12-slim

# Security: run as non-root user
RUN groupadd -r rootprint && useradd -r -g rootprint -s /sbin/nologin rootprint

WORKDIR /app

# Copy files with correct ownership
COPY --chown=rootprint:rootprint server.py .
COPY --chown=rootprint:rootprint static/ ./static/

# Create data directory with restricted permissions
RUN mkdir -p data && chown rootprint:rootprint data && chmod 700 data

# Drop root
USER rootprint

EXPOSE 7117

HEALTHCHECK --interval=30s --timeout=8s --start-period=15s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:7117/api/health')" || exit 1

# No shell — exec form prevents shell injection
CMD ["python", "-u", "server.py"]
