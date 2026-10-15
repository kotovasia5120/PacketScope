FROM python:3.12.7-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update \
    && apt-get install --no-install-recommends --yes make \
    && rm -rf /var/lib/apt/lists/*

COPY Makefile pyproject.toml README.md requirements.lock ./
COPY packetscope ./packetscope
COPY tests ./tests

RUN python -m packetscope.build_backend --check \
    && python -m compileall -q packetscope tests \
    && make test

EXPOSE 8765
CMD ["python", "-m", "packetscope.cli", "serve", "--host", "0.0.0.0", "--port", "8765"]
