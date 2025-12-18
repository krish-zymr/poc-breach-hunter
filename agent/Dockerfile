FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY agent/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY agent/ /app/
COPY breach_hunter_client.py /app/breach_hunter_client.py

RUN chmod +x /app/run_sample_agent.sh

CMD ["sh", "./run_sample_agent.sh"]


