# Mailgaze container image.
#
# Kept deliberately small and dependency-light so it builds on the free tier of
# any host. The app needs no database, no API keys and no persistent storage —
# it holds nothing between requests — so a single stateless container is the
# whole deployment.

FROM python:3.12-slim

# Don't buffer stdout, so logs appear in the host's log viewer immediately,
# and don't write .pyc files into the image layer.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    MAILGAZE_ENV=production \
    HOST=0.0.0.0 \
    PORT=7860

WORKDIR /app

# Dependencies first: this layer is cached and only rebuilds when
# requirements.txt changes, which makes redeploys fast.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/
COPY samples/ ./samples/
COPY run.py .

# Run as a non-root user. Nothing here needs elevated privileges.
RUN useradd --create-home --uid 1000 mailgaze && chown -R mailgaze:mailgaze /app
USER mailgaze

EXPOSE 7860

CMD ["python", "run.py"]
