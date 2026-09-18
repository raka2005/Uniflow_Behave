from scapy.all import rdpcap, IP, TCP, UDP, ICMP
from collections import defaultdict
from pathlib import Path
import csv
import sys


# --------------------------------------------------
# 1. Read PCAP file
# --------------------------------------------------

pcap_file = (
    sys.argv[1]
    if len(sys.argv) > 1
    else "dataset/threats.pcap"
)

print("=" * 80)
print("SIH26145 Passive AI-Based Cyber-Threat Detection")
print("PCAP Analyzer Started")
print("=" * 80)

try:
    packets = rdpcap(pcap_file)

except FileNotFoundError:
    print("\nError: PCAP file not found:")
    print(pcap_file)
    print("\nPlease check the file path.")
    sys.exit(1)

except Exception as error:
    print("\nError while reading PCAP file:")
    print(error)
    sys.exit(1)

print(f"PCAP file: {pcap_file}")
print(f"Total packets analyzed: {len(packets)}")


# --------------------------------------------------
# 2. Extract flow information
# --------------------------------------------------

flows = defaultdict(lambda: {
    "packet_count": 0,
    "total_bytes": 0,
    "destination_ports": set(),
    "syn_count": 0,
    "ack_count": 0,
    "icmp_count": 0
})


for packet in packets:

    # Ignore packets without IPv4 information
    if IP not in packet:
        continue

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    protocol = "OTHER"
    src_port = 0
    dst_port = 0

    # ------------------------------
    # TCP packet
    # ------------------------------

    if TCP in packet:

        protocol = "TCP"
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

    # ------------------------------
    # UDP packet
    # ------------------------------

    elif UDP in packet:

        protocol = "UDP"
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    # ------------------------------
    # ICMP packet
    # ------------------------------

    elif ICMP in packet:

        protocol = "ICMP"

    flow_key = (
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol
    )

    flow = flows[flow_key]

    flow["packet_count"] += 1
    flow["total_bytes"] += len(packet)

    # Count destination ports
    if dst_port != 0:
        flow["destination_ports"].add(dst_port)

    # ------------------------------
    # Count TCP flags
    # ------------------------------

    if TCP in packet:

        flags = int(packet[TCP].flags)

        # SYN flag
        if flags & 0x02:
            flow["syn_count"] += 1

        # ACK flag
        if flags & 0x10:
            flow["ack_count"] += 1

    # ------------------------------
    # Count ICMP packets
    # ------------------------------

    if ICMP in packet:

        flow["icmp_count"] += 1


print(f"Total flows extracted: {len(flows)}")


# --------------------------------------------------
# 3. Threat detection
# --------------------------------------------------

threats = []

source_port_scan = defaultdict(set)
source_packet_count = defaultdict(int)


for flow_key, flow_data in flows.items():

    src_ip, dst_ip, src_port, dst_port, protocol = flow_key

    packet_count = flow_data["packet_count"]
    total_bytes = flow_data["total_bytes"]

    syn_count = flow_data["syn_count"]
    ack_count = flow_data["ack_count"]
    icmp_count = flow_data["icmp_count"]

    # Count destination ports contacted by each source
    if dst_port != 0:
        source_port_scan[src_ip].add(dst_port)

    # Count total packets sent by each source
    source_packet_count[src_ip] += packet_count

    # --------------------------------------------------
    # 3.1 High-volume UDP detection
    # --------------------------------------------------

    if protocol == "UDP" and packet_count >= 100:

        threats.append({
            "threat_type": "High-Volume UDP Traffic",
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "protocol": protocol,
            "packet_count": packet_count,
            "total_bytes": total_bytes,
            "severity": "High",
            "risk_score": 90,
            "description": (
                "Large number of UDP packets detected"
            )
        })

    # --------------------------------------------------
    # 3.2 SYN Flood detection
    # --------------------------------------------------

    if (
        protocol == "TCP"
        and syn_count >= 50
        and ack_count < syn_count * 0.2
    ):

        threats.append({
            "threat_type": "Possible SYN Flood",
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "protocol": "TCP",
            "packet_count": packet_count,
            "total_bytes": total_bytes,
            "severity": "High",
            "risk_score": 95,
            "description": (
                f"High SYN count: {syn_count}, "
                f"low ACK response: {ack_count}"
            )
        })

    # --------------------------------------------------
    # 3.3 ICMP Flood detection
    # --------------------------------------------------

    if (
        protocol == "ICMP"
        and icmp_count >= 100
    ):

        threats.append({
            "threat_type": "Possible ICMP Flood",
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "protocol": "ICMP",
            "packet_count": packet_count,
            "total_bytes": total_bytes,
            "severity": "High",
            "risk_score": 90,
            "description": (
                f"High ICMP packet volume: "
                f"{icmp_count} packets"
            )
        })


# --------------------------------------------------
# 4. Port scan detection
# --------------------------------------------------

for src_ip, ports in source_port_scan.items():

    if len(ports) >= 10:

        threats.append({
            "threat_type": "Possible Port Scan",
            "source_ip": src_ip,
            "destination_ip": "Multiple",
            "protocol": "TCP/UDP",
            "packet_count": source_packet_count[src_ip],
            "total_bytes": 0,
            "severity": "High",
            "risk_score": 85,
            "description": (
                f"Source contacted {len(ports)} "
                f"different destination ports"
            )
        })


# --------------------------------------------------
# 5. Group DNS traffic as normal traffic
# --------------------------------------------------

dns_traffic = defaultdict(lambda: {
    "packet_count": 0,
    "total_bytes": 0
})


for flow_key, flow_data in flows.items():

    src_ip, dst_ip, src_port, dst_port, protocol = flow_key

    if protocol == "UDP" and dst_port == 53:

        dns_key = (src_ip, dst_ip)

        dns_traffic[dns_key]["packet_count"] += (
            flow_data["packet_count"]
        )

        dns_traffic[dns_key]["total_bytes"] += (
            flow_data["total_bytes"]
        )


# DNS traffic is grouped for reporting.
# It is not counted as a threat automatically.


# --------------------------------------------------
# 6. Display detected threats
# --------------------------------------------------

print("\n")
print("=" * 80)
print("THREAT DETECTION RESULTS")
print("=" * 80)


if len(threats) == 0:

    print("No suspicious activity detected.")

else:

    for index, threat in enumerate(threats, start=1):

        print(f"\nThreat {index}")
        print(f"Type: {threat['threat_type']}")
        print(f"Source IP: {threat['source_ip']}")
        print(f"Destination IP: {threat['destination_ip']}")
        print(f"Protocol: {threat['protocol']}")
        print(f"Packets: {threat['packet_count']}")
        print(f"Total bytes: {threat['total_bytes']}")
        print(f"Severity: {threat['severity']}")
        print(f"Risk Score: {threat['risk_score']}/100")
        print(f"Description: {threat['description']}")


# --------------------------------------------------
# 7. Create reports folder
# --------------------------------------------------

reports_folder = Path("reports")
reports_folder.mkdir(exist_ok=True)


# --------------------------------------------------
# 8. Save flow report
# --------------------------------------------------

flow_csv_file = reports_folder / "flows.csv"

with open(
    flow_csv_file,
    "w",
    newline="",
    encoding="utf-8"
) as file:

    writer = csv.writer(file)

    writer.writerow([
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "protocol",
        "packet_count",
        "total_bytes",
        "destination_ports",
        "syn_count",
        "ack_count",
        "icmp_count"
    ])

    for flow_key, flow_data in flows.items():

        src_ip, dst_ip, src_port, dst_port, protocol = flow_key

        writer.writerow([
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            flow_data["packet_count"],
            flow_data["total_bytes"],
            len(flow_data["destination_ports"]),
            flow_data["syn_count"],
            flow_data["ack_count"],
            flow_data["icmp_count"]
        ])


# --------------------------------------------------
# 9. Save threat report
# --------------------------------------------------

threat_csv_file = reports_folder / "threats.csv"

with open(
    threat_csv_file,
    "w",
    newline="",
    encoding="utf-8"
) as file:

    writer = csv.writer(file)

    writer.writerow([
        "threat_type",
        "source_ip",
        "destination_ip",
        "protocol",
        "packet_count",
        "total_bytes",
        "severity",
        "risk_score",
        "description"
    ])

    for threat in threats:

        writer.writerow([
            threat["threat_type"],
            threat["source_ip"],
            threat["destination_ip"],
            threat["protocol"],
            threat["packet_count"],
            threat["total_bytes"],
            threat["severity"],
            threat["risk_score"],
            threat["description"]
        ])


# --------------------------------------------------
# 10. Risk summary
# --------------------------------------------------

high_threats = 0
medium_threats = 0
low_threats = 0

total_risk_score = 0


for threat in threats:

    total_risk_score += threat["risk_score"]

    if threat["severity"] == "High":
        high_threats += 1

    elif threat["severity"] == "Medium":
        medium_threats += 1

    elif threat["severity"] == "Low":
        low_threats += 1


if len(threats) > 0:

    average_risk_score = (
        total_risk_score / len(threats)
    )

else:

    average_risk_score = 0


if average_risk_score >= 70:

    overall_risk = "High"

elif average_risk_score >= 40:

    overall_risk = "Medium"

else:

    overall_risk = "Low"


# --------------------------------------------------
# 11. Display risk summary
# --------------------------------------------------

print("\n")
print("=" * 80)
print("NETWORK RISK SUMMARY")
print("=" * 80)

print(f"High-severity threats: {high_threats}")
print(f"Medium-severity threats: {medium_threats}")
print(f"Low-severity threats: {low_threats}")
print(f"Average risk score: {average_risk_score:.2f}/100")
print(f"Overall network risk: {overall_risk}")

print("=" * 80)


# --------------------------------------------------
# 12. Final result
# --------------------------------------------------

print("\n")
print("=" * 80)
print("FINAL RESULT")
print("=" * 80)

print(f"Total packets analyzed: {len(packets)}")
print(f"Total flows detected: {len(flows)}")
print(f"Total threats detected: {len(threats)}")
print(f"Flow report saved to: {flow_csv_file}")
print(f"Threat report saved to: {threat_csv_file}")

print("=" * 80)