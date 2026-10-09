FROM mcr.microsoft.com/playwright/python:v1.49.0-noble

ENV PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive \
    HOME=/tmp \
    PORT=8001

WORKDIR /app

# Install system dependencies (zbar for QR, Tesseract OCR for text on image lures)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libzbar0 \
    tesseract-ocr tesseract-ocr-eng tesseract-ocr-rus tesseract-ocr-chi-sim \
    libgl1 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ /app/src/

# Run playwright browser install
RUN playwright install chromium

USER 1000:1000

EXPOSE 8001

CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8001"]
