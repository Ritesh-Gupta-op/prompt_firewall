FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app

COPY backend/pyproject.toml backend/README.md /app/backend/
COPY backend/src /app/backend/src
RUN pip install --no-cache-dir -e /app/backend

COPY . /app
EXPOSE 8000
CMD ["uvicorn", "promptfirewall.main:app", "--app-dir", "backend/src", "--host", "0.0.0.0", "--port", "8000"]
