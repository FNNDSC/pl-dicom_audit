FROM docker.io/python:3.12.1-slim-bookworm

LABEL org.opencontainers.image.authors="FNNDSC <dev@babyMRI.org>" \
      org.opencontainers.image.title="A ChRIS plugin to audit DICOM de-identification" \
      org.opencontainers.image.description="Builds a de-identification audit (crosswalks, per-file change log, residual-PHI checks) by diffing identified and de-identified DICOM trees"

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
