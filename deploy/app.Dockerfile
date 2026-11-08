FROM docker:29-cli@sha256:2357639ad1ea7d0194134bf3292622fd4e562483966ed674e5d7c945b5f3b28d AS docker_cli
FROM python:3.13-slim-bookworm@sha256:a5a7017efc5969e00ae2b91c8eb0631049a569652aa4ffc4501769049ae45c72 AS app
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/srv/backend HOME=/tmp
WORKDIR /srv
COPY backend/requirements.lock /srv/backend/requirements.lock
RUN python -m pip install --no-cache-dir -r backend/requirements.lock
COPY backend/app /srv/backend/app
COPY backend/alembic.ini /srv/backend/alembic.ini
COPY backend/migrations /srv/backend/migrations
COPY samples/controlled /srv/samples/controlled
COPY deploy/validator /srv/deploy/validator
RUN mkdir /srv/data && chown 1000:1000 /srv/data
USER 1000:1000
FROM app AS runner
# This controller is trusted and privileged through its socket. API/worker use target app.
COPY --from=docker_cli /usr/local/bin/docker /usr/local/bin/docker
USER 0:0
