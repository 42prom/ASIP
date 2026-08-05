# The core image — API, scheduler, migrations.
#
# Everything that is allowed to hold a database credential. The counterpart is
# Dockerfile.fetcher, which is a different image because the fetch zone is a
# different trust boundary (D-11, V-3): an image that cannot reach postgres
# cannot accidentally start doing so.
#
# One image, several entrypoints. The API and the scheduler share every
# dependency and every line of the composition root; building them separately
# would mean two things to keep in step for no isolation benefit, since both
# hold the same credentials by design.

FROM python:3.12-slim

# Non-root. This container does hold the database credential, which is exactly
# why it should not also be able to rewrite its own filesystem.
RUN useradd --create-home --uid 10002 asip

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src
COPY config ./config
COPY migrations ./migrations
COPY web ./web

RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir .

USER asip

# Unbuffered so a container log shows the tick that is happening rather than
# the one that happened before the buffer filled. For a process whose job is to
# be observable, this is not a nicety.
ENV PYTHONUNBUFFERED=1

# No default entrypoint: this image serves the API, the scheduler and the
# migration runner, and compose names which. A default would make one of them
# look canonical.
CMD ["python", "-m", "asip.entrypoints.scheduler", "--help"]
