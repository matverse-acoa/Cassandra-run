FROM python:3.11-slim

RUN apt-get update && apt-get install -y libssl-dev

WORKDIR /app

COPY runtime /app/runtime
COPY pbse_cli /usr/local/bin/pbse_cli
COPY docker/entrypoint.sh /entrypoint.sh

RUN chmod +x /usr/local/bin/pbse_cli /entrypoint.sh

RUN pip install fastapi uvicorn

EXPOSE 8545

ENTRYPOINT ["/entrypoint.sh"]
CMD ["uvicorn", "runtime.main:app", "--host", "0.0.0.0", "--port", "8545"]
