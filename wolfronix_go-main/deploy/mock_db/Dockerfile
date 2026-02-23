FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir flask gunicorn

COPY mock_client_api.py .

# Create storage directory
RUN mkdir -p mock_storage/files mock_storage/keys

EXPOSE 4000

# Use gunicorn for production (4 workers, handles concurrent requests)
CMD ["gunicorn", "--bind", "0.0.0.0:4000", "--workers", "4", "--timeout", "600", "mock_client_api:app"]
