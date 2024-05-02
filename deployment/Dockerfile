# this Dockerfile builds docker.io/openziti/ziti-cli

# get kubectl CLI from a source with Docker Content Trust (DCT)
# FIXME: require DCT at build time
FROM bitnami/kubectl as bitnami-kubectl

# FIXME: This repo requires terms acceptance and is only available on registry.redhat.io.
# FROM registry.access.redhat.com/openshift4/ose-cli as openshift-cli  

FROM registry.access.redhat.com/ubi9/ubi-minimal
# This build stage grabs artifacts that are copied into the final image.
# It uses the same base as the final image to maximize docker cache hits.

ARG ARTIFACTS_DIR=build
ARG DOCKER_BUILD_DIR=.
# e.g. linux
ARG TARGETOS
# e.g. arm64
ARG TARGETARCH

ARG ZUID=2171
ARG ZGID=2171

### Required OpenShift Labels 
LABEL name="openziti/pod-controller" \
      maintainer="developers@openziti.org" \
      vendor="NetFoundry" \
      summary="Run the OpenZiti Controller" \
      description="Run the OpenZiti Controller"

USER root

### install packages
RUN   INSTALL_PKGS="python3.11 python3.11-pip tar bash-completion vim-minimal less shadow-utils jq findutils hostname" && \
      microdnf -y update --setopt=install_weak_deps=0 --setopt=tsflags=nodocs && \
      microdnf -y install --setopt=install_weak_deps=0 --setopt=tsflags=nodocs ${INSTALL_PKGS} && \
      microdnf clean all

### install OpenShift CLI (oc)
# FIXME: This repo requires terms acceptance and is only available on registry.redhat.io.
# COPY --from=openshift-cli  /path/to/oc /usr/local/bin/oc

### install Kubernetes CLI
COPY --from=bitnami-kubectl /opt/bitnami/kubectl/bin/kubectl /usr/local/bin/

RUN groupadd --gid ${ZGID} ziggy \
      && adduser --uid ${ZUID} --gid ${ZGID} --system --home /home/ziggy --shell /bin/bash ziggy \
      && mkdir -p /home/ziggy \
      && chown -R ${ZUID}:${ZGID} /home/ziggy \
      && chmod -R g+rwX /home/ziggy
RUN mkdir -p /usr/local/bin
COPY ${ARTIFACTS_DIR}/ziti-agent-wh /usr/local/bin/
COPY ${ARTIFACTS_DIR}/*.pem /home/ziggy/
RUN chmod 0600 -R /home/ziggy
RUN chown ziggy:ziggy -R /home/ziggy
RUN chmod 0755 /usr/local/bin/ziti-agent-wh

USER ziggy
COPY ${DOCKER_BUILD_DIR}/deployment/bashrc /home/ziggy/.bashrc
ENTRYPOINT [ "ziti-agent-wh" ]
