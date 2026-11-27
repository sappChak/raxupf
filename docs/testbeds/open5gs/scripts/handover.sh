#!/usr/bin/env bash
# Captures a PacketRusher UE that registers, runs iperf3 through the UPF, hands
# over to the other gNB mid-transfer, keeps sending, and deregisters.
#
# Usage: scripts/handover.sh [xn|ng]
#   Env: DURATION (s, default 20), HANDOVER_AT (s, default 10),
#        BITRATE (iperf3 -b, default 2M), REVERSE=1 (downlink iperf3),
#        PROTOCOL (UDP/TCP, default tcp), OUT (output directory, default captures/)
#
# Needs the stack running with the packetrusher profile. Writes
# <OUT>/handover-<type>-<timestamp>.pcap with N2 (NGAP), N3 (GTP-U) and N4 (PFCP),
# and the iperf3 log next to it.
set -euo pipefail

TYPE=${1:-xn}
DURATION=${DURATION:-20}
HANDOVER_AT=${HANDOVER_AT:-10}
BITRATE=${BITRATE:-2M}
REVERSE=${REVERSE:-0}
PROTOCOL=${PROTOCOL:-tcp}
PROJECT_DIR=$(cd "$(dirname "$0")/.." && pwd)
OUT=${OUT:-$PROJECT_DIR/captures}

DN_ADDR=$(grep -E '^DN_IPV4_ADDRESS=' "$PROJECT_DIR/.env" | cut -d= -f2)
CAPTURE_IMAGE=raxupf-dn:latest
VRF=vrf0000000002
UE_DEV=val0000000002

case "$TYPE" in
  xn) ACTION=xn-handover ;;
  ng) ACTION=ng-handover ;;
  *) echo "usage: $0 [xn|ng]" >&2; exit 2 ;;
esac
(( HANDOVER_AT < DURATION )) || { echo "HANDOVER_AT must be less than DURATION" >&2; exit 2; }

log() { printf '\033[1m[%s] %s\033[0m\n' "$(date +%T)" "$*"; }

control() {
  docker exec packetrusher /packetrusher/packetrusher control \
    --socket /run/packetrusher.sock "$@"
}

# The gNB the UE is on, and the other one (the handover target).
current_gnb() { control | sed -n 's/.*"gnb": "\([0-9A-Fa-f]*\)".*/\1/p' | head -1; }
other_gnb() {
  control | sed -n 's/.*"id": "\([0-9A-Fa-f]*\)".*/\1/p' | grep -vx "$1" | head -1
}

CAPTURES=()
cleanup() {
  for name in "${CAPTURES[@]}"; do docker stop -t 2 "$name" >/dev/null 2>&1 || true; done
}
trap cleanup EXIT SIGINT SIGTERM

capture() { # <name> <netns container> <filter> <file>
  docker run -d --rm --name "$1" --net "container:$2" --cap-add NET_RAW --cap-add NET_ADMIN \
    -v "$OUT:/out" "$CAPTURE_IMAGE" \
    tcpdump -ni eth0 -U -w "/out/$(basename "$4")" "$3" >/dev/null
  CAPTURES+=("$1")
}

# --- preconditions ---------------------------------------------------------
docker exec packetrusher test -S /run/packetrusher.sock 2>/dev/null || {
  echo "packetrusher is not running: COMPOSE_PROFILES=packetrusher docker compose up -d" >&2
  exit 1
}
mkdir -p "$OUT"
STAMP=$(date +%Y%m%d-%H%M%S)
BASE="$OUT/handover-$TYPE-$STAMP"

log "Deregistering the UE, so the capture starts from a clean state"
control --ue 1 --action deregister >/dev/null || true

# --- capture ---------------------------------------------------------------
# N2 + N3 from the RAN side (the UPF's XDP hides N3 from captures in its own
# namespace), N4 from the SMF.
capture "cap-ran-$STAMP" packetrusher 'sctp or udp port 2152' "$BASE.ran.pcap"
capture "cap-n4-$STAMP" open5gs-smf 'udp port 8805' "$BASE.n4.pcap"
sleep 2

log "Registering the UE (PFCP Session Establishment)"
control --ue 1 --action register >/dev/null
SOURCE=$(current_gnb)
TARGET=$(other_gnb "$SOURCE")
UE_ADDR=$(docker exec packetrusher ip -4 -o addr show "$UE_DEV" | awk '{print $4}' | cut -d/ -f1)
log "UE $UE_ADDR on gNB $SOURCE, handover target gNB $TARGET"

IPERF_PORT=5299   # one-off server, apart from any interactive one on 5201
docker exec -d dn iperf3 -s -1 -p "$IPERF_PORT"
sleep 1

DIRECTION=uplink; IPERF_ARGS=()
if [[ "$REVERSE" == 1 ]]; then DIRECTION=downlink; IPERF_ARGS=(-R); fi
if [[ "$PROTOCOL" == udp ]]; then IPERF_ARGS+=(-u); fi
log "iperf3 $PROTOCOL in $DIRECTION at $BITRATE for ${DURATION}s, $TYPE handover at ${HANDOVER_AT}s"
docker exec packetrusher ip vrf exec "$VRF" \
  iperf3 -c "$DN_ADDR" -p "$IPERF_PORT"  -t "$DURATION" -b "$BITRATE" -i 1 --forceflush "${IPERF_ARGS[@]}" \
  > "$BASE.iperf3.log" 2>&1 &
IPERF_PID=$!

sleep "$HANDOVER_AT"
log "Handover $SOURCE -> $TARGET ($ACTION)"
control --ue 1 --action "$ACTION" --target "$TARGET" >/dev/null
log "UE now on gNB $(current_gnb)"

wait "$IPERF_PID" || { log "iperf3 failed:"; cat "$BASE.iperf3.log"; exit 1; }

log "Deregistering the UE (PFCP Session Deletion)"
control --ue 1 --action deregister >/dev/null
sleep 2
cleanup
CAPTURES=()

docker run --rm -v "$OUT:/out" --user "$(id -u):$(id -g)" "$CAPTURE_IMAGE" \
  mergecap -w "/out/$(basename "$BASE").pcap" \
  "/out/$(basename "$BASE").ran.pcap" "/out/$(basename "$BASE").n4.pcap"
docker run --rm -v "$OUT:/out" "$CAPTURE_IMAGE" \
  rm -f "/out/$(basename "$BASE").ran.pcap" "/out/$(basename "$BASE").n4.pcap"

log "Restoring the UE for interactive use"
control --ue 1 --action register >/dev/null || true

# --- summary ---------------------------------------------------------------
echo
grep -E '^\[ *[0-9]+\] +[0-9.]+-[0-9.]+ +sec' "$BASE.iperf3.log" | grep -v -E 'sender|receiver' || true
grep -E 'sender|receiver' "$BASE.iperf3.log" || true
echo
docker run --rm -v "$OUT:/out:ro" "$CAPTURE_IMAGE" \
  tshark -r "/out/$(basename "$BASE").pcap" \
  -Y '(pfcp && pfcp.msg_type > 2) || ngap' \
  -T fields -e frame.time_relative -e ip.src -e ip.dst -e _ws.col.Info 2>/dev/null \
  | awk -F'\t' '{printf "%8.3f  %-13s -> %-13s %s\n", $1, $2, $3, $4}' || true
echo
log "Capture: $BASE.pcap"
log "iperf3:  $BASE.iperf3.log"
