# Bandit with every dependency pinned (constraints.txt is `pip freeze` of this image).
FROM python:3.12-slim@sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f
COPY constraints.txt /tmp/constraints.txt
RUN pip install --no-cache-dir -c /tmp/constraints.txt "bandit[sarif]==1.9.4"
