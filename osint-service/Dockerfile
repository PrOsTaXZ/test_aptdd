# OSINT Service: проверка номеров инструментом Personal OSINT Toolkit (vendor/) и ников через Maigret.
FROM python:3.13-slim
RUN useradd --system --uid 10001 tip
WORKDIR /app
COPY requirements.txt requirements-maigret.txt ./
RUN pip install --no-cache-dir -r requirements.txt \
 && python3 -m venv /opt/maigret && /opt/maigret/bin/pip install --no-cache-dir -r requirements-maigret.txt
ENV OSINT_MAIGRET_PYTHON=/opt/maigret/bin/python
COPY service.py osint_modules.py ./
COPY vendor ./vendor
USER tip
ENV PYTHONUNBUFFERED=1
CMD ["python3", "service.py"]
