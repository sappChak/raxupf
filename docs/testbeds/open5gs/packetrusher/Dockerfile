ARG GO_VERSION=1.26.2
FROM golang:${GO_VERSION}-bookworm AS builder

# Pinned PacketRusher release, known to work with this testbed.
ARG PACKETRUSHER_REF=v2.0.0

WORKDIR /src
RUN git clone --depth 1 --branch ${PACKETRUSHER_REF} https://github.com/HewlettPackard/PacketRusher . \
    && go mod download \
    && CGO_ENABLED=0 go build -trimpath -ldflags "-X main.version=${PACKETRUSHER_REF}" -o /out/packetrusher ./cmd

FROM debian:bookworm-slim
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
       ca-certificates iproute2 iputils-ping iperf3 sockperf ethtool tcpdump \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /packetrusher
COPY --from=builder /out/packetrusher /packetrusher/packetrusher
COPY entrypoint.sh /packetrusher/entrypoint.sh

# SIGINT lets PacketRusher deregister the UE and remove its tunnel before exiting.
STOPSIGNAL SIGINT
ENTRYPOINT ["sh", "/packetrusher/entrypoint.sh"]
CMD ["ue"]
