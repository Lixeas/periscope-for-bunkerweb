FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    PERISCOPE_DATABASE_URL=sqlite:////data/periscope.db

RUN useradd --create-home --uid 10001 periscope && mkdir /data && chown periscope /data
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir .

USER periscope
VOLUME /data
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/login').status == 200 else 1)"

# FORWARDED_ALLOW_IPS (lu par uvicorn) : IP du reverse proxy autorisé à fixer X-Forwarded-For.
CMD ["uvicorn", "periscope.web.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]
