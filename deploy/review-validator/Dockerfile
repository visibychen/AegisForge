# Additive reviewed tests; the original validator files and image remain unchanged.
FROM aegisforge-validator:m4
COPY review_harness.py review_cases.py /opt/review-validator/
ARG VALIDATOR_FINGERPRINT
LABEL org.aegisforge.validator=$VALIDATOR_FINGERPRINT
ENTRYPOINT ["python", "/opt/review-validator/review_harness.py"]
