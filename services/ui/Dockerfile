FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1     ROOT_DIR=/app

WORKDIR /app

COPY services/ui/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# The UI talks to the worker REST API; demo fixtures are synthetic samples (no customer data).
COPY services/ui/app.py services/ui/backend.py services/ui/render.py /app/services/ui/

EXPOSE 8501

CMD ["streamlit", "run", "services/ui/app.py", "--server.port=8501", "--server.address=0.0.0.0"]
