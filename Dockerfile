FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server.py .

# Database volume for persistence
VOLUME ["/app/data"]
ENV DUCKDB_PATH=/app/data/mcptrust.duckdb

EXPOSE 8000

CMD ["python", "server.py"]
