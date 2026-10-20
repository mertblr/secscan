FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

ENV FORWARDED_ALLOW_IPS="*"

CMD ["sh", "-c", "fastapi run main.py --host 0.0.0.0 --port ${PORT:-8000}"]