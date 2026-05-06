FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install Gradio and PyNEAT
RUN pip install --no-cache-dir \
    gradio>=4.44.0 \
    pyneat-cli>=3.0.0

# Copy the app
COPY . .

ENV PYTHONUNBUFFERED=1
ENV PORT=7860

EXPOSE 7860

# Run with Gradio's built-in server
CMD ["python", "app.py"]
