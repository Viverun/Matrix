#!/bin/bash

# Start the background worker
echo "Starting RQ Worker..."
python rq_worker.py &

# Start the web server
echo "Starting Gunicorn..."
gunicorn main:app -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:$PORT
