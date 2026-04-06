FROM python:3.11-slim

LABEL maintainer="ApiRed"
LABEL description="API Security Testing Platform"

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    wget \
    git \
    chromium \
    chromium-driver \
    && rm -rf /var/lib/apt/lists/*

# Set Chromium environment variables
ENV CHROME_BIN=/usr/bin/chromium
ENV CHROMEDRIVER_PATH=/usr/bin/chromedriver

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install Playwright browsers
RUN playwright install --with-deps chromium

# Copy application code
COPY . .

# Create non-root user
RUN useradd -m -u 1000 apired && \
    chown -R apired:apired /app

USER apired

# Expose default port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Default command
CMD ["python", "-m", "core.engine", "--target", "http://localhost:8000"]
