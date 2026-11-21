FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN useradd -m -u 1000 appuser

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY app/ /app/app/
COPY web/ /app/web/

RUN chown -R appuser:appuser /app

USER appuser

EXPOSE 8086

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8086"]
