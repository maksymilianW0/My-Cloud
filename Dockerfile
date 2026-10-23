FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY src/main.py .
COPY src/static/ ./static/
RUN mkdir data

CMD ["python", "main.py"]
