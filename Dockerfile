ARG python_version=3.10
FROM --platform=linux/amd64 python:${python_version}-slim AS base

WORKDIR /usr/src/app

# Install and configure poetry
ENV POETRY_VERSION=1.8.3
ENV POETRY_HOME=/opt/poetry

RUN apt-get update && apt-get install --yes curl && apt-get clean

RUN curl -sSL https://install.python-poetry.org | python3 -

ENV PATH="/opt/poetry/bin:$PATH"
RUN poetry config virtualenvs.in-project true

# Setup project
COPY pyproject.toml poetry.lock README.md ./
COPY acapy_wallet_upgrade/ acapy_wallet_upgrade/
COPY askar_tools/ askar_tools/
RUN poetry build


FROM --platform=linux/amd64 python:${python_version}-slim AS askar-tools
COPY --from=base /usr/src/app/dist/askar_tools-*-py3-none-any.whl /tmp/.

RUN pip install /tmp/askar_tools-*-py3-none-any.whl && \
        rm /tmp/askar_tools-*

ENTRYPOINT /bin/bash
