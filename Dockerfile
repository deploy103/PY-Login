FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir --disable-pip-version-check -r requirements.txt \
    && addgroup --system app \
    && adduser --system --ingroup app --home /app --no-create-home app

COPY --chown=app:app app.py ./
COPY --chown=app:app services ./services
COPY --chown=app:app static ./static
COPY --chown=app:app templates ./templates

RUN mkdir -p /app/data && chown app:app /app/data

USER app

EXPOSE 8000

CMD ["gunicorn", "--bind=0.0.0.0:8000", "--workers=1", "--access-logfile=-", "--error-logfile=-", "--capture-output", "app:app"]
