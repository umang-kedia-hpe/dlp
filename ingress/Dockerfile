FROM python:3.11-slim

WORKDIR /app

COPY ingress/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY ingress/app.py .
COPY utilkit.py ./utilkit.py

EXPOSE 8081

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8081"]