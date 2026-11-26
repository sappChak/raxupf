# Open5GS testbed

A self-contained 5G SA network in Docker Compose for exercising a UPF over
PFCP (N4) and GTP-U (N3). The control plane is [Open5GS], and the UPF is
[eUPF] by default. Swap in another UPF to test it. The RAN and UE are simulated
by [UERANSIM] or [PacketRusher], or both at once:

- **UERANSIM** (default) is good for signalling and light traffic. Under
  sustained load, such as iperf3, its simulated radio link drops ("Radio link
  failure").
- **PacketRusher** runs the gNB and UE in one process with an eBPF GTP-U
  tunnel. Use it for throughput and long-running traffic.

[Open5GS]: https://github.com/open5gs/open5gs
[UERANSIM]: https://github.com/aligungr/UERANSIM
[PacketRusher]: https://github.com/HewlettPackard/PacketRusher
[eUPF]: https://github.com/edgecomllc/eupf

## Topology

All containers share a single bridge, `br-open5gs` (`172.20.0.0/24`), so N2,
N3, N4, N6 and SBI traffic can be captured in one place.


```
                       AMF .120 ── SBI ── SMF .110
                          │                  │
                  N2 (NGAP, sctp/38412)  N4 (PFCP, udp/8805)
                          │                  │
UE .150 ── radio ── gNB .140 ── N3 (GTP-U) ── UPF .130 ── N6 ── DN .155
 uesimtun0                     udp/2152    │           (plain IPv4)
                                           │
PacketRusher .160/.161 ── N2/N3 ───────────┘
 (2 gNBs + UE, vrf0000000002)

UE pool: 10.60.0.0/16
```

| Component | Address        | Notes                                     |
|-----------|----------------|-------------------------------------------|
| AMF       | 172.20.0.120   | NGAP on `38412/sctp`                      |
| SMF       | 172.20.0.110   | PFCP client                               |
| UPF       | 172.20.0.130   | PFCP `8805/udp`, GTP-U `2152/udp`, XDP    |
| gNB       | 172.20.0.140   | UERANSIM `nr-gnb` (profile `ueransim`)    |
| UE        | 172.20.0.150   | UERANSIM `nr-ue`, `uesimtun0` in the pool |
| PacketRusher | 172.20.0.160, .161 | 2 gNBs + UE (profile `packetrusher`), VRF `vrf0000000002` |
| DN        | 172.20.0.155   | N6 peer with traffic tools                |
| UE pool   | 10.60.0.0/16   | Allocated by the SMF                      |

All addresses are defined in [`.env`](.env). YAML configs can't read `.env`,
so some values are repeated:

- If you change the UPF address or the UE pool, update `config/eupf.yaml` and
  `config/smf.yaml`.
- If you change the PacketRusher or AMF address, update
  `config/packetrusher.yml`.

## Test parameters

| Parameter       | Value                              |
|-----------------|------------------------------------|
| PLMN            | MCC `999`, MNC `70` (test network) |
| TAC             | `1`                                |
| S-NSSAI         | SST `1`, no SD                     |
| DNN             | `internet`, IPv4                   |
| IMSI (UERANSIM) | `999700000000001`                  |
| IMSI (PacketRusher) | `999700000000002`              |
| K (both)        | `465B5CE8B199B49FAA5F0A2EE238A6BC` |
| OPc (both)      | `E8ED289DEBA952E4283B54E88E6183CA` |
| SUCI protection | null scheme (SUPI in clear text)   |
| NAS ciphering   | NEA0 preferred (readable NAS)      |
| Session AMBR    | 1 Gbps UL/DL, enforced by the UPF  |

Both subscribers are provisioned by [`add_subscriber.js`](add_subscriber.js).
They have separate IMSIs, so both RANs can be registered at the same time.

## Requirements

- Linux with Docker Engine and the Compose plugin.
- A kernel with XDP/eBPF support. The UPF runs privileged and mounts
  `/sys/fs/bpf`.
- The `sctp` kernel module, used by NGAP: `sudo modprobe sctp`.
- For PacketRusher's eBPF tunnel backend: Linux 6.6 or later. Its container
  runs privileged. On older kernels, PacketRusher falls back to its slower
  userspace backend.
- No other process on the host bound to UDP `8805` or `2152` on all addresses.

## Running

Build the Open5GS image once. It compiles Open5GS from a pinned revision and
takes a few minutes:

```sh
docker build -t open5gs-base ./base
```

### Choosing the RAN

The RAN simulators are Compose profiles. `COMPOSE_PROFILES` in `.env`
chooses which ones start (`ueransim` by default). Override it per command:

```sh
docker compose up -d --build                                          # UERANSIM (default)
COMPOSE_PROFILES=packetrusher docker compose up -d --build            # PacketRusher only
COMPOSE_PROFILES=ueransim,packetrusher docker compose up -d --build   # both
docker compose ps
```

Use one RAN per capture, so the pcap only holds one UE's PFCP session.

Stop the testbed. `--profile '*'` includes every RAN, whichever ones were
started. `-v` also drops the MongoDB volume, so the subscribers are
provisioned again on the next start:

```sh
docker compose --profile '*' down -v
```

### UERANSIM

The UE registers and sets up a PDU session automatically. Check it with:

```sh
docker logs ue | grep "PDU Session"
docker exec ue ip -4 addr show uesimtun0
```

Send traffic from the UE through the UPF to the DN:

```sh
docker exec ue ping -I uesimtun0 -c 4 172.20.0.155
```

For short bursts of heavier traffic, the DN image has `iperf3`, `sockperf`,
`hping3` and `flent`. For sustained load, use PacketRusher instead.

```sh
docker exec -d dn iperf3 -s
docker exec ue sh -c 'apt-get update && apt-get install -y iperf3'   # once per container
UE_IP=$(docker exec ue ip -4 -o addr show uesimtun0 | awk '{print $4}' | cut -d/ -f1)
docker exec ue iperf3 -c 172.20.0.155 -B "$UE_IP" -t 5        # uplink
docker exec ue iperf3 -c 172.20.0.155 -B "$UE_IP" -t 5 -R     # downlink
```

### PacketRusher

The `packetrusher` container runs two gNBs and one UE:

| gNB      | N2/N3 address | Role                          |
|----------|---------------|-------------------------------|
| `000002` | 172.20.0.160  | serves the UE at registration |
| `000003` | 172.20.0.161  | handover target               |

The UE `imsi-999700000000002` registers, establishes one PDU session and keeps
it up. Its address sits in VRF `vrf0000000002` (`vrf<MSIN>`), so commands must
run inside that VRF to go through the tunnel:

```sh
docker logs packetrusher | grep -E "PDU session 1 address|tunnel backend"

docker exec packetrusher ip vrf exec vrf0000000002 ping -c 4 172.20.0.155

docker exec -d dn iperf3 -s
docker exec packetrusher ip vrf exec vrf0000000002 iperf3 -c 172.20.0.155 -t 30       # uplink
docker exec packetrusher ip vrf exec vrf0000000002 iperf3 -c 172.20.0.155 -t 30 -R    # downlink
docker exec packetrusher ip vrf exec vrf0000000002 iperf3 -c 172.20.0.155 -P 4        # 4 streams
```

`iperf3`, `sockperf`, `ping` and `tcpdump` are in the image. Throughput is
capped at about 1 Gbps by the subscriber's session AMBR, which the eUPF
enforces. Raise `ambr` in `add_subscriber.js` (then `down -v`) for more.

#### Driving the UE

While it runs, the UE takes commands on a control socket. Each command waits
for the procedure to finish and prints the state of the UE and gNBs:

```sh
alias prctl='docker exec packetrusher /packetrusher/packetrusher control --socket /run/packetrusher.sock'

prctl                                                    # state: UE's gNB, PDU sessions
prctl --ue 1 --action xn-handover --target 000003        # Xn handover (Path Switch)
prctl --ue 1 --action ng-handover --target 000002        # N2 handover (via the AMF)
prctl --ue 1 --action deregister                         # -> PFCP Session Deletion
prctl --ue 1 --action register                           # -> PFCP Session Establishment + Modification
prctl --ue 1 --action idle                               # AN release
prctl --ue 1 --action reconnect                          # service request
```

Stopping the container (`docker compose stop packetrusher`) sends SIGINT.
PacketRusher deregisters the UE first. `docker compose start packetrusher`
registers it again on gNB `000002`.

#### Handover with traffic

[`scenarios/handover.sh`](scenarios/handover.sh) captures a complete handover
with traffic:

1. Deregister the UE and start capturing.
2. Register the UE (PFCP Session Establishment).
3. Run iperf3 through the UPF.
4. Hand the UE over to the other gNB mid-transfer, while traffic continues.
5. Deregister (PFCP Session Deletion), stop capturing, and register the UE
   again for interactive use.

```sh
COMPOSE_PROFILES=packetrusher docker compose up -d --build

./scenarios/handover.sh xn                       # Xn handover, uplink iperf3
REVERSE=1 ./scenarios/handover.sh ng             # N2 handover, downlink iperf3
DURATION=30 HANDOVER_AT=15 BITRATE=5M ./scenarios/handover.sh xn
```

| Variable      | Default     | Meaning                                  |
|---------------|-------------|------------------------------------------|
| `DURATION`    | `20`        | iperf3 duration, seconds                 |
| `HANDOVER_AT` | `10`        | seconds into iperf3 before the handover  |
| `BITRATE`     | `2M`        | iperf3 `-b` (keeps the pcap small)       |
| `REVERSE`     | `0`         | `1` for downlink traffic                 |
| `OUT`         | `captures/` | output directory (ignored by git)        |

The script writes `captures/handover-<xn|ng>-<timestamp>.pcap` and the iperf3
log, and prints the per-second rate and the NGAP/PFCP sequence. The pcap merges
the RAN side (N2 NGAP and N3 GTP-U for both gNB addresses) with the SMF side (N4
PFCP). The handover shows up on N4 as one PFCP Session Modification that
updates the downlink FAR's outer header to the new gNB address and TEID:

```
Xn:  PathSwitchRequest -> PFCP Session Modification -> PathSwitchRequestAcknowledge
N2:  HandoverRequired -> HandoverRequest/Ack -> HandoverCommand -> HandoverNotify
     -> PFCP Session Modification
```

The default bitrate gives about 6 MB of pcap for 20 s.

#### One-off runs

For other PacketRusher scenarios, run a one-off container with a different
subcommand. Stop the long-running one first, because both would use the same
gNB addresses and IMSI:

```sh
docker compose stop packetrusher
docker compose run --rm packetrusher multi-ue -n 1 --tunnel --loop --loopCount 3 --timeBeforeDeregistration 5000
docker compose run --rm packetrusher --help
docker compose start packetrusher
```

`multi-ue` keeps its gNBs running after the UEs finish, until you press
Ctrl-C. `multi-ue -n N` uses consecutive MSINs from `0000000002`. Only that
first UE has a subscriber, so add more to `add_subscriber.js` before using
`N > 1`.

The gNB, UE and AMF settings are in
[`config/packetrusher.yml`](config/packetrusher.yml). Extra gNBs take the next
IP addresses and gNB IDs after the configured ones. Image builds are pinned to
PacketRusher `v2.0.0` (`PACKETRUSHER_REF` in `packetrusher/Dockerfile`).

## Capturing PFCP and GTP-U

The UPF processes GTP-U in XDP, before the kernel's packet taps. **A capture
taken inside the UPF container will not show N3 traffic.** Capture from a
peer's network namespace or from the host bridge instead.

Everything on the core network, from the host:

```sh
sudo tcpdump -i br-open5gs -w capture.pcap 'udp port 8805 or udp port 2152'
```

Without root on the host, from the gNB's namespace (N3) or the SMF's (N4):

```sh
docker run --rm --net container:gnb --cap-add NET_RAW raxupf-dn:latest \
  tcpdump -ni eth0 -U -w - 'udp port 2152' > n3.pcap

docker run --rm --net container:open5gs-smf --cap-add NET_RAW raxupf-dn:latest \
  tcpdump -ni eth0 -U -w - 'udp port 8805' > n4.pcap
```

With PacketRusher, `tcpdump` is in its image, and its `eth0` shows the N3
traffic:

```sh
docker exec packetrusher tcpdump -ni eth0 -U -w - 'udp port 2152' > n3.pcap
```

To capture a full lifecycle, start the capture first and then (re)start the
stack. This records association setup, session establishment and
modification, user traffic and session deletion:

```sh
sudo tcpdump -i br-open5gs -w session.pcap 'udp port 8805 or udp port 2152' &
docker compose up -d
docker exec ue ping -I uesimtun0 -c 4 172.20.0.155
docker exec ue ./nr-cli imsi-999700000000001 -e "ps-release 1"
```

The PDU session can also be driven by hand with `nr-cli`, without restarting
anything:

```sh
docker exec ue ./nr-cli imsi-999700000000001 -e "ps-release 1"                              # -> PFCP Session Deletion
docker exec ue ./nr-cli imsi-999700000000001 -e "ps-establish IPv4 --sst 1 --dnn internet"  # -> PFCP Session Establishment + Modification
docker exec ue ./nr-cli imsi-999700000000001 -e "ps-list"
```

With PacketRusher, use the control socket (`prctl --ue 1 --action
deregister` / `register`, see above) or `scenarios/handover.sh`.

PFCP heartbeats are frequent. Filter them out when reading a capture with
`pfcp.msg_type != 1 && pfcp.msg_type != 2` in Wireshark or `tshark -Y`.

Wireshark decodes PFCP on `8805/udp` and GTP-U on `2152/udp` out of the box.

## Testing another UPF

The `upf` service is the only component under test. To replace it, point it at
another image and config while keeping the address `172.20.0.130` and the
`upf.open5gs.org` alias. The SMF associates with `upf.open5gs.org` and
allocates UE addresses and F-TEIDs itself. The UPF does not need UE IP or
F-TEID allocation (`feature_ueip` and `feature_ftup` are off).

The UPF must forward uplink N6 traffic out of `eth0`. The DN routes the UE
pool back through `172.20.0.130`. There is no NAT and no Internet access from
the UE: the DN is the only reachable N6 peer.

After a handover, the downlink goes to a gNB address (`172.20.0.161`) that the
UPF may never have exchanged packets with. An XDP UPF that looks up the next
hop with `bpf_fib_lookup` then gets `BPF_FIB_LKUP_RET_NO_NEIGH`, because its
kernel has no ARP entry for that address. The eUPF drops the downlink in that
case. To avoid this, PacketRusher pings the UPF from each extra gNB address at
startup, which makes the UPF's kernel resolve them. To test how your UPF
handles a missing neighbour, set `ARP_PRIME_TARGET` to an empty value for the
`packetrusher` service in `docker-compose.yaml`.

## Web UI

The Open5GS web UI is published on <http://localhost:9999> (default login
`admin` / `1423`) and can be used to inspect or add subscribers.

## Troubleshooting

- **UE registration rejected**: the subscriber in MongoDB does not match
  `config/ue.yaml` or `config/packetrusher.yml`. MongoDB only runs
  `add_subscriber.js` on a fresh volume, so run
  `docker compose --profile '*' down -v` after changing it.
- **UERANSIM "Radio link failure" during iperf3**: UERANSIM's simulated radio
  link can't keep up with sustained load. Use PacketRusher for traffic tests.
- **Downlink stops after a handover, uplink still works**: the UPF has no ARP
  entry for the new gNB address (see "Testing another UPF"). Check with
  `docker run --rm --net container:upf raxupf-dn:latest ip neigh`.
- **No traffic after restarting only the `upf` service**: the UPF lost its PFCP
  sessions and its neighbour table, while the UE still thinks its session is
  up. Restart the RAN too (`docker compose restart packetrusher`, or `gnb ue`),
  so the UE re-registers and the UPF learns the gNB addresses again.
- **Why the UPF, gNB, PacketRusher and DN have fixed MAC addresses**: an XDP
  UPF forwards using its kernel's neighbour entries, and XDP traffic never
  refreshes them. With Docker's default random MACs, restarting a peer left the
  UPF sending to the old MAC, which silently dropped all traffic in that
  direction.
- **`packetrusher` keeps running after `docker compose down`**: the command
  only covers the active profiles. Use `docker compose --profile '*' down`.
- **Ping works but TCP/UDP downlink does not**: the DN's TX checksum offload
  is on (`docker exec dn ethtool -k eth0 | grep tx-checksumming`). On veth,
  offload leaves checksums unfinished, and an XDP UPF that encapsulates the
  packet as-is delivers a corrupt checksum to the UE. The `dn` service
  disables it at startup.
- **PDU session up but ping fails**: check that `n3_address` in
  `config/eupf.yaml` matches the UPF container address, and that the route on
  the DN exists (`docker exec dn ip route`).
- Open5GS logs: `docker logs open5gs-<nf>`, or `/var/log/open5gs/<nf>.log`
  inside the container.
