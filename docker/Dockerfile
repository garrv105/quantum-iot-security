FROM python:3.12-slim

LABEL maintainer="Garrv Sipani <fgarrvs1@jh.edu>"
LABEL description="Quantum-Enhanced IoT Security Platform"

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN pip install --no-cache-dir -e .

EXPOSE 8000

CMD ["uvicorn", "quantum_iot_security.api.server:app", "--host", "0.0.0.0", "--port", "8000"]
