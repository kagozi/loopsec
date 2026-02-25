FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

RUN mkdir -p uploads

# Create a non-root user and switch to it
RUN useradd -m appuser
USER appuser

EXPOSE 5001
CMD ["python", "app.py"]