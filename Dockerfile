FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    DATA_DIR=/data

# Użytkownik bez uprawnień roota + katalog na dane
RUN useradd --create-home --uid 1000 app \
    && mkdir /data \
    && chown app:app /data

WORKDIR /app

# Zależności w osobnej warstwie – cache działa, dopóki requirements.txt się nie zmieni
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY --chown=app:app src/main.py .
COPY --chown=app:app src/static/ ./static/

USER app
VOLUME /data
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request as u; u.urlopen('http://127.0.0.1:8080/api/public', timeout=3)" || exit 1

CMD ["python", "main.py"]