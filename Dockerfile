FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
COPY tg_userbot_mcp_railway.zip /tmp/app.zip
RUN python -m zipfile -e /tmp/app.zip /app && rm /tmp/app.zip
WORKDIR /app/tg_userbot_mcp
RUN pip install -r requirements.lock.txt
COPY overrides/ ./
RUN python check.py
ENV HOST=0.0.0.0 TRUSTED_PROXY=* DATA_DIR=/data
CMD ["python", "server.py"]
