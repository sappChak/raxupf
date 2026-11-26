#!/bin/sh
# Docker gives a container one address per network. PacketRusher runs extra gNBs
# (handover targets) on the next N2/N3 addresses, so add them to eth0 first.
set -e

PRIMARY=$(ip -4 -o addr show dev eth0 | awk '{print $4; exit}')
for addr in ${EXTRA_GNB_ADDRESSES}; do
  ip addr replace "${addr}" dev eth0
done

# XDP UPFs (eUPF, raxupf) pick the next-hop MAC with bpf_fib_lookup, which
# fails (NO_NEIGH) for a gNB address the UPF's kernel has not resolved. GTP-U
# alone never makes it resolve one, because XDP consumes the packets before the
# kernel sees them. Without an entry, the downlink to that gNB is dropped.
# Pinging the UPF from every gNB address makes its kernel resolve them all.
# Leave ARP_PRIME_TARGET empty to test without this.
if [ -n "${ARP_PRIME_TARGET}" ]; then
  for addr in ${PRIMARY} ${EXTRA_GNB_ADDRESSES}; do
    src=${addr%/*}
    primed=no
    for _ in 1 2 3 4 5; do
      if ping -q -c 1 -W 1 -I "${src}" "${ARP_PRIME_TARGET}" >/dev/null 2>&1; then
        primed=yes
        break
      fi
    done
    [ "${primed}" = yes ] || echo "warning: ${ARP_PRIME_TARGET} did not answer from ${src}" >&2
  done
fi

exec /packetrusher/packetrusher --config /packetrusher/config/config.yml "$@"
