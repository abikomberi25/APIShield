FROM python:3.12-slim

WORKDIR /app

# Create a non-root user for security
RUN addgroup --system apishield && adduser --system --ingroup apishield apishield

# Install Python dependencies first (layer-caching optimization)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source (excluding .env, .venv, *.db, __pycache__)
COPY backend/ backend/
COPY detection/ detection/
COPY attacks/ attacks/
COPY scripts/ scripts/
COPY docs/ docs/

# Environment configuration
# JWT_SECRET must be provided at runtime — never hardcode secrets in images
ENV JWT_SECRET=""
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Transfer ownership to non-root user
RUN chown -R apishield:apishield /app
USER apishield

EXPOSE 8000

# Liveness probe using the /health endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" \
    || exit 1

# Start the FastAPI server
CMD ["python", "-m", "uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
