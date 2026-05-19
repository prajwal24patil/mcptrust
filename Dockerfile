FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY mcptrust_server.py .

ENV DUCKDB_PATH=/app/mcptrust.duckdb

EXPOSE 8000

CMD ["python", "mcptrust_server.py"]
