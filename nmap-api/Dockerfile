FROM python:3.11-slim

LABEL maintainer="Tesis Seguridad Informatica"
LABEL description="Microservicio REST para Nmap - Proyecto 01"

# Instalar nmap y dependencias del sistema
RUN apt-get update && apt-get install -y \
    nmap \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Instalar dependencias Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

EXPOSE 5000

# Nmap necesita capabilities para algunos tipos de scan (SYN scan, OS detection)
# Estas capabilities se otorgan en docker-compose con cap_add
CMD ["python", "app.py"]