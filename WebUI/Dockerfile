FROM python:3.10.20-slim-trixie


RUN useradd --system --user-group --shell /bin/false appuser


COPY --chown=appuser:appuser ./app /app
# COPY --chown=appuser:appuser templates/ ./templates/

WORKDIR /app

# RUN ls -la
# RUN pwd

RUN pip install --no-cache-dir -r requirements.txt

USER appuser

EXPOSE 80


CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "80"]