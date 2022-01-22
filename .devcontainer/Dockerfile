FROM ubuntu:focal

ENV DEBIAN_FRONTEND=noninteractive

RUN sed --in-place=~ 's|archive.ubuntu.com|ftp.acc.umu.se|g' /etc/apt/sources.list

# Base tools for Dlang
ARG DMD_VERSION=2.098.1
ARG DSTEP_VERSION=1.0.0

RUN apt-get update \
    && apt-get install \
        --no-install-recommends \
        --assume-yes \
        --quiet \
        ca-certificates \
        curl \
        gcc \
        libc6-dev \
        pkg-config \
        xz-utils \
    && rm -r /var/lib/apt/lists/* \
    && curl \
        --location \
        --fail \
        --show-error \
        --silent \
        --output /tmp/dmd_${DMD_VERSION}-0_amd64.deb \
        http://downloads.dlang.org/releases/2021/dmd_${DMD_VERSION}-0_amd64.deb \
    && dpkg -i /tmp/dmd_${DMD_VERSION}-0_amd64.deb \
    && rm /tmp/dmd_${DMD_VERSION}-0_amd64.deb \
    && curl \
        --location \
        --fail \
        --show-error \
        --silent \
        https://github.com/jacob-carlborg/dstep/releases/download/v1.0.0/dstep-${DSTEP_VERSION}-linux-x86_64.tar.xz \
    |tar -x --xz --directory /usr/local/bin

# Other useful tools
RUN apt-get update \
    && apt-get install \
        --no-install-recommends \
        --assume-yes \
        --quiet \
        git \
        less \
        netcat \
    && rm -r /var/lib/apt/lists/*

# project-specific dependencies
RUN apt-get update \
    && apt-get install \
        --no-install-recommends \
        --assume-yes \
        --quiet \
        openssl \
        libssl-dev \
    && rm -r /var/lib/apt/lists/*

RUN useradd \
        --uid 1000 \
        --shell /bin/bash \
        --create-home \
        build

# Don't run as root inside container,
# see https://github.com/microsoft/vscode-remote-release/issues/22
ENV HOME /home/build
USER build

CMD ["/bin/bash", "-l"]
