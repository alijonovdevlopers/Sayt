FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
COPY requirements.lock.txt .
RUN pip install -r requirements.lock.txt
COPY . .
ENV HOST=0.0.0.0 TRUSTED_PROXY=* DATA_DIR=/data
CMD ["python", "server.py"]
