FROM python:3.9-slim

WORKDIR /app
COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY c2_listener.py .
EXPOSE 443
CMD ["python", "c2_listener.py"]