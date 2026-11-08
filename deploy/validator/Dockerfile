FROM python:3.13-slim-bookworm@sha256:a5a7017efc5969e00ae2b91c8eb0631049a569652aa4ffc4501769049ae45c72
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PLAYWRIGHT_BROWSERS_PATH=/opt/playwright HOME=/tmp
COPY requirements.lock /opt/validator/requirements.lock
RUN python -m pip install --no-cache-dir --require-hashes -r /opt/validator/requirements.lock \
    && python -m playwright install --with-deps chromium \
    && chmod -R a+rX /opt/playwright \
    && printf '#!/bin/sh\nexit 0\n' > /usr/local/bin/ping \
    && chmod 755 /usr/local/bin/ping
COPY harness.py target.py ping_stub.py target_guard.py /opt/validator/
# A /bin/sh wrapper (not a shebang in the copied file) keeps CRLF checkouts from breaking exec.
RUN printf '#!/bin/sh\nexec /usr/local/bin/python /opt/validator/ping_stub.py "$@"\n' > /usr/local/bin/ping \
    && chmod 755 /usr/local/bin/ping
ARG VALIDATOR_FINGERPRINT
LABEL org.aegisforge.validator=$VALIDATOR_FINGERPRINT
USER 65532:65532
WORKDIR /tmp
ENTRYPOINT ["python", "/opt/validator/harness.py"]
