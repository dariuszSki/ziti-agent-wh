ARG ZITI_CLI_TAG="latest"
ARG ZITI_CLI_IMAGE="docker.io/openziti/ziti-cli"

# this builds docker.io/openziti/ziti-k8s-agent
FROM ${ZITI_CLI_IMAGE}:${ZITI_CLI_TAG}

ARG ARTIFACTS_DIR=build
ARG DOCKER_BUILD_DIR=.

### Required OpenShift Labels
LABEL name="openziti/ziti-router" \
      maintainer="developers@openziti.org" \
      vendor="NetFoundry" \
      summary="Run the OpenZiti Router" \
      description="Run the OpenZiti Router"

# set up image as root
USER root

# install artifacts as root
COPY ${ARTIFACTS_DIR}/ziti-agent-wh /usr/local/bin/
COPY ${ARTIFACTS_DIR}/*.pem /home/ziggy/
RUN chmod 0755 /usr/local/bin/ziti-agent-wh
RUN chmod 0755 /home/ziggy/*.pem

USER ziggy
#COPY ${DOCKER_BUILD_DIR}/deployment/bashrc /home/ziggy/.bashrc
ENTRYPOINT [ "ziti-agent-wh" ]
