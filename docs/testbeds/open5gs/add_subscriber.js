// Runs once, when the MongoDB volume is first created.
// Must match config/ue.yaml (UERANSIM) and config/packetrusher.yml (PacketRusher).
db = db.getSiblingDB("open5gs");

const K = "465B5CE8B199B49FAA5F0A2EE238A6BC";
const OPC = "E8ED289DEBA952E4283B54E88E6183CA";

const ambr = {
    uplink: { value: 1, unit: 3 },   // 1 Gbps
    downlink: { value: 1, unit: 3 },
};

function subscriber(imsi) {
    return {
        imsi: imsi,
        msisdn: [],
        imeisv: [],
        mme_host: [],
        mme_realm: [],
        purge_flag: [],
        security: { k: K, opc: OPC, op: null, amf: "8000", sqn: NumberLong(0) },
        ambr: ambr,
        slice: [
            {
                sst: 1,
                default_indicator: true,
                session: [
                    {
                        name: "internet",
                        type: 1, // IPv4
                        qos: {
                            index: 9,
                            arp: {
                                priority_level: 8,
                                pre_emption_capability: 1,
                                pre_emption_vulnerability: 1,
                            },
                        },
                        ambr: ambr,
                        pcc_rule: [],
                    },
                ],
            },
        ],
        access_restriction_data: 32,
        subscriber_status: 0,
        network_access_mode: 0,
        subscribed_rau_tau_timer: 12,
        schema_version: 1,
    };
}

db.subscribers.insertMany([
    subscriber("999700000000001"), // UERANSIM UE
    subscriber("999700000000002"), // PacketRusher UE
]);
