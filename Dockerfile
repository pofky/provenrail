FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir -e ".[anchor]"

ENV FR_DB=/data/flightrecorder.db
VOLUME ["/data"]
EXPOSE 8000

# append-only sink with real trusted timestamps
CMD ["sh", "-c", "fr serve --host 0.0.0.0 --port 8000 --db ${FR_DB} --anchor rfc3161"]
