FROM python:3.10.20-slim-trixie

ARG USER_UID
ARG USER_GID

RUN groupadd --gid $USER_GID appuser \
    && useradd --uid $USER_UID --gid $USER_GID --system --shell /bin/false appuser

COPY --chown=appuser:appuser ./app /app
WORKDIR /app

RUN pip install --no-cache-dir -r requirements.txt

USER appuser
ENV PYTHONUNBUFFERED=1
EXPOSE 80

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "80", "--log-level", "debug"]