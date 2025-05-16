#!/bin/sh

set -e

echo "Starting Django backend..."

# Wait for the PostgreSQL database
echo "Waiting for database..."

echo "Running migrations..."
pdm run python solarsys.py migrate

echo "Creating superuser..."
pdm run python solarsys.py createsuperuser --noinput --email admin@solarsys.org --password admin || true

echo "Collecting static files..."
pdm run python solarsys.py collectstatic --noinput

echo "Starting Gunicorn..."
exec pdm run gunicorn config.wsgi:application --bind 0.0.0.0:8000 --workers=4
