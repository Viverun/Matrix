#!/bin/bash

echo "=== Matrix Backend Starting ==="
echo "PORT: $PORT"
echo "Environment: $ENVIRONMENT"

# Run database migrations
echo "Running database migrations..."
alembic upgrade head
if [ $? -ne 0 ]; then
    echo "WARNING: Migration failed, but continuing startup..."
fi

# Start the background worker (don't fail if Redis is unavailable)
echo "Starting RQ Worker..."
python rq_worker.py &
WORKER_PID=$!
echo "Worker started with PID: $WORKER_PID"

# Start the web server (this is critical)
echo "Starting Gunicorn on port $PORT..."
gunicorn main:app -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:$PORT --log-level info
