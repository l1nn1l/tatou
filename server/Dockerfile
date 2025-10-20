# Server image: minimal Flask + Gunicorn
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates openssh-client \
 && rm -rf /var/lib/apt/lists/*

# Copy project description, to instal dependencies
COPY pyproject.toml /app/pyproject.toml

# Install runtime dependencies
RUN pip install --no-cache-dir -e .

# Copy sources after dependencies installation
COPY src /app/src

# Copy flag only if it exists
RUN if [ -f flag ]; then cp flag /app/flag; else echo "flag not found, skipping"; fi

COPY entrypoint.sh /app/entrypoint.sh
RUN pip install --no-cache-dir -e .

EXPOSE 5000

# Default command runs the web server
CMD ["./entrypoint.sh"]

