FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

COPY pyproject.toml README.md alembic.ini ./
COPY src ./src

RUN pip install --no-cache-dir . \
    && useradd --system --uid 10001 --home-dir /var/lib/signur --create-home signur

USER 10001:10001

CMD ["uvicorn", "signur.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-proxy-headers"]
