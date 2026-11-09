FROM python:3.12-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends unzip && rm -rf /var/lib/apt/lists/*
COPY tg_userbot_mcp_railway.zip /tmp/app.zip
RUN unzip -q /tmp/app.zip -d /app
# DIAGNOSTIC: print structure and start command, then stop
RUN echo '=== TREE ===' && find /app -maxdepth 3 -not -path '*/__pycache__*' | sort \
 && echo '=== SERVICE ===' && (cat /app/*/deploy/tg-mcp.service /app/deploy/tg-mcp.service 2>/dev/null || true) \
 && echo '=== REQUIREMENTS ===' && (cat /app/*/requirements.txt /app/requirements.txt 2>/dev/null || true) \
 && echo '=== ENTRYPOINTS ===' && (grep -rn "__main__\|uvicorn\|PORT\|argparse" /app --include=*.py | head -40 || true) \
 && exit 1
