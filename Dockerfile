FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TZ=Europe/Moscow

WORKDIR /app

RUN pip install --no-cache-dir httpx python-dotenv

COPY itmo_client.py bot.py ./

CMD ["python", "bot.py"]

