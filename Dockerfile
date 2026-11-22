FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Dedicated non-root UID (10001) so the container does not inherit host UID 1000
# privileges (e.g. tailscale --operator) when reading /var/run/tailscale/tailscaled.sock.
RUN useradd -m -u 10001 appuser

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY app/ /app/app/
COPY web/ /app/web/

RUN chown -R appuser:appuser /app

USER appuser

EXPOSE 8086

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8086"]
