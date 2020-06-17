FROM ubuntu:20.04

ENV DEBIAN_FRONTEND="noninteractive"
RUN apt-get update && \
  apt-get install -y apt-transport-https ca-certificates gnupg \
    software-properties-common wget build-essential git libssl-dev && \
  wget -O - https://apt.kitware.com/keys/kitware-archive-latest.asc 2>/dev/null \
    | gpg --dearmor - \
    | tee /etc/apt/trusted.gpg.d/kitware.gpg >/dev/null && \
  apt-add-repository 'deb https://apt.kitware.com/ubuntu/ focal main' && \
  apt-get update && \
  apt-get install -y cmake

WORKDIR /uthenticode

ARG PEPARSE_VERSION
RUN git clone --branch "${PEPARSE_VERSION}" \
  https://github.com/trailofbits/pe-parse && \
  mkdir -p pe-parse/build && \
  cd pe-parse/build && \
  cmake .. && make && make install

ENV CMAKE_PREFIX_PATH=/uthenticode/pe-parse/build/lib/cmake/pe-parse
