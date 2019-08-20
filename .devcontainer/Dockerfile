FROM ubuntu:bionic

ENV DEBIAN_FRONTEND=noninteractive

RUN sed --in-place=~ 's|archive.ubuntu.com|ftp.acc.umu.se|g' /etc/apt/sources.list \
    && apt-get update \
    && apt-get \
        --no-install-recommends \
        --assume-yes \
        --quiet \
        upgrade

# Base tools
RUN apt-get install \
        --no-install-recommends \
        --assume-yes \
        --quiet \
        ca-certificates \
        curl \
        git \
        less \
        netcat \
        xz-utils

# dlang-tools
RUN apt-get install \
        --no-install-recommends \
        --assume-yes \
        --quiet \
        gcc \
        libc6-dev \
        pkg-config \
    && curl \
        --location \
        --fail \
        --show-error \
        --silent \
        --output /tmp/dmd_amd64.deb \
        http://downloads.dlang.org/releases/2.x/2.086.1/dmd_2.086.1-0_amd64.deb \
    && dpkg -i /tmp/dmd_amd64.deb \
    && rm /tmp/dmd_amd64.deb \
    && curl \
        --location \
        --fail \
        --show-error \
        --silent \
        https://github.com/jacob-carlborg/dstep/releases/download/v1.0.0/dstep-1.0.0-linux-x86_64.tar.xz \
    | tar -x --xz --directory /usr/local/bin

# project-specific dependencies
RUN apt-get install \
        --no-install-recommends \
        --assume-yes \
        --quiet \
        openssl \
        libssl-dev

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
