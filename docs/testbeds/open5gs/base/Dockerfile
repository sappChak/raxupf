FROM ubuntu:22.04

# Pinned Open5GS revision (v2.8.0+), known to work with this testbed.
ARG OPEN5GS_REF=5877b43196fca0b185b266f6616979c86c962a4c

ENV DEBIAN_FRONTEND=noninteractive \
    INSTALL_PREFIX=/opt/open5gs/install

RUN apt-get update && \
    apt-get install -y ca-certificates curl gnupg && \
    mkdir -p /etc/apt/keyrings && \
    curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg && \
    NODE_MAJOR=20 && \
    echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_$NODE_MAJOR.x nodistro main" | tee /etc/apt/sources.list.d/nodesource.list

RUN apt-get update && \
    apt-get install -y nodejs \
      python3-pip python3-setuptools python3-wheel \
      ninja-build build-essential flex bison cmake \
      libsctp-dev libgnutls28-dev libgcrypt-dev libssl-dev \
      libmongoc-dev libbson-dev libyaml-dev libnghttp2-dev \
      libmicrohttpd-dev libcurl4-gnutls-dev libtins-dev \
      libtalloc-dev meson pkg-config git \
      iproute2 iputils-ping iptables && \
    if apt-cache show libidn-dev > /dev/null 2>&1; then \
      apt-get install -y --no-install-recommends libidn-dev; \
    else \
      apt-get install -y --no-install-recommends libidn11-dev; \
    fi && \
    rm -rf /var/lib/apt/lists/*

RUN git clone https://github.com/open5gs/open5gs /opt/open5gs && \
    cd /opt/open5gs && \
    git checkout ${OPEN5GS_REF} && \
    meson build --prefix=${INSTALL_PREFIX} && \
    ninja -C build && \
    cd build && \
    ninja install

RUN cd /opt/open5gs/webui && \
    npm ci

RUN mkdir -p /var/log/open5gs && chmod 755 /var/log/open5gs

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

WORKDIR /opt/open5gs
ENTRYPOINT ["/entrypoint.sh"]
