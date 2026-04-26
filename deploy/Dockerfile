FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY server/requirements.txt /app/server/requirements.txt
RUN pip install -r /app/server/requirements.txt

COPY server /app/server
COPY .env.example /app/.env.example

# 默认从 /app/.env 读取（compose 中以 env_file 注入也可）
EXPOSE 5060/udp 8000/tcp 20000-20199/udp

CMD ["python", "-m", "server.main"]
