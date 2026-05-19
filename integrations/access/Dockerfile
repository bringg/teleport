ARG BASE_IMAGE=gcr.io/distroless/static-debian12

# BUILDPLATFORM is provided by Docker/buildx
# Extract the built tarball to reduce the final image size
FROM --platform=${BUILDPLATFORM} alpine:3.20.0 AS extractor

ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG ARTIFACT_NAME=access-incidentio
ARG TELEPORT_VERSION=18.8.1
ARG FILENAME=teleport-${ARTIFACT_NAME}-v${TELEPORT_VERSION}-${TARGETOS}-${TARGETARCH}-bin.tar.gz # Optional override

WORKDIR /extraction
COPY *${TARGETARCH}*.tar.gz /plugin.tar.gz
COPY "${FILENAME}" /plugin.tar.gz

RUN tar -xzvf /plugin.tar.gz && \
    find . -type f -executable -name 'teleport-*' -exec mv {} /teleport-plugin \;

# Create the image with the build operator on the $TARGETPLATFORM
# TARGETPLATFORM is provided by Docker/buildx
# --platform=${TARGETPLATFORM} is set by default and the docker linter complains if we set it.
FROM ${BASE_IMAGE}
WORKDIR /
COPY --from=extractor /teleport-plugin /usr/local/bin/teleport-plugin

ENTRYPOINT ["/usr/local/bin/teleport-plugin"]
