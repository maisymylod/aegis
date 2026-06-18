FROM python:3.12-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1

COPY pyproject.toml ./
COPY src ./src
RUN pip install --no-cache-dir ".[service]"

EXPOSE 8600
CMD ["uvicorn", "aegis.service:app", "--host", "0.0.0.0", "--port", "8600"]
