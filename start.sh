

# Start Flask API via gunicorn
exec gunicorn anchor_api_server:app --bind "0.0.0.0:${PORT:-8080}" --workers 2 --timeout 120