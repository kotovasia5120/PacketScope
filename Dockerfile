FROM python:3.12.7-slim@sha256:1c44018d7eb40488f29e7c6ad4991d3200507e14dca71b94fe61011815e98155

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
