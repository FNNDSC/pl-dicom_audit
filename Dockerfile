FROM docker.io/python:3.12.1-slim-bookworm

LABEL org.opencontainers.image.authors="FNNDSC <dev@babyMRI.org>" \
      org.opencontainers.image.title="A ChRIS plugin to audit DICOM anonymization" \
      org.opencontainers.image.description="Records what pl-dicom_anonymize changed (identifier, UID and date mappings, per-file tag changes) and scans its output for leaked original values"

ARG SRCDIR=/usr/local/src/pl-dicom_audit
WORKDIR ${SRCDIR}

COPY requirements.txt .
RUN --mount=type=cache,sharing=private,target=/root/.cache/pip pip install -r requirements.txt

COPY . .
ARG extras_require=none
RUN pip install ".[${extras_require}]" \
    && cd / && rm -rf ${SRCDIR}
WORKDIR /

CMD ["dicom_audit"]
