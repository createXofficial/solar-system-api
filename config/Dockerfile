# Base Python image
FROM python:3.13.3-alpine

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set working directory
WORKDIR /app

# Install OS-level dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install PDM globally
RUN curl -sSL https://pdm.fming.dev/install-pdm.py | python3 && \
    ln -s /root/.local/bin/pdm /usr/local/bin/pdm

# Copy only dependency files first for caching
COPY pyproject.toml pdm.lock ./

# Install dependencies (excluding dev)
RUN pdm install --prod --no-editable

# Copy project code
COPY . .
COPY .env /app/.env

# Collect static files
RUN pdm run python manage.py collectstatic --noinput

# Run Gunicorn server
CMD ["pdm", "run", "gunicorn", "config.wsgi:application", "--bind", "0.0.0.0:8000"]
