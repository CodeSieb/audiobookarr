FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install Node.js 18
RUN curl -fsSL https://deb.nodesource.com/setup_18.x | bash - \
    && apt-get install -y nodejs

# Copy Python requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy frontend and build
COPY frontend/ ./frontend/
WORKDIR /app/frontend
RUN npm install && npm run build

# Copy backend
WORKDIR /app
COPY main.py .

# Create directories
RUN mkdir -p /audiobooks /app/data

# Set permissions
RUN chmod 755 /audiobooks /app/data

EXPOSE 8080

ENV AUDIOBOOKS_DIR=/audiobooks
ENV APP_PORT=8080
ENV PYTHONPATH=/app

CMD ["python", "main.py"]