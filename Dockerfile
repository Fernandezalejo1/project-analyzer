FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Dependencias primero para aprovechar la caché de capas
COPY backend/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir pytest

COPY backend/pyproject.toml ./pyproject.toml
COPY backend/app ./app
COPY backend/tests ./tests

EXPOSE 8000

# El analyzer necesita acceso de lectura a proyectos y a git
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
