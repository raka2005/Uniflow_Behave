from scapy.all import sniff, wrpcap, rdpcap, IP, TCP, UDP
from collections import defaultdict
import os


DATASET_FOLDER = "dataset"


# --------------------------------------------------
# Create normal dataset
# --------------------------------------------------

def create_normal_dataset():

    os.makedirs(DATASET_FOLDER, exist_ok=True)

    print("Capturing normal traffic...")
    print("Perform normal browsing activity.")
    print("Press Ctrl+C to stop capturing.")

    packets = []

    try:
        packets = sniff()

    except KeyboardInterrupt:
        print("\nCapture stopped by user.")

    if len(packets) == 0:
        print("No packets captured.")
        return None

    file_path = os.path.join(
        DATASET_FOLDER,
        "normal.pcap"
    )

    wrpcap(file_path, packets)

    print("Normal dataset saved.")
    print("File:", file_path)
    print("Total packets captured:", len(packets))

    return file_path


# --------------------------------------------------
# Analyze PCAP dataset
# --------------------------------------------------

def analyze_pcap(file_path):

    packets = rdpcap(file_path)

    flows = defaultdict(lambda: {
        "packet_count": 0,
        "byte_count": 0,
        "syn_count": 0,
        "ack_count": 0,
        "rst_count": 0,
        "src_ports": set(),
        "dst_ports": set(),
        "dst_ips": set(),
        "first_time": None,
        "last_time": None
    })

    for packet in packets:

        if not packet.haslayer(IP):
            continue

        ip_layer = packet[IP]

        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = ip_layer.proto

        src_port = None
        dst_port = None

        if packet.haslayer(TCP):

            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport

        elif packet.haslayer(UDP):

            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        # Flow is grouped by source IP, destination IP and protocol
        flow_key = (
            src_ip,
            dst_ip,
            protocol
        )

        flow = flows[flow_key]

        flow["packet_count"] += 1
        flow["byte_count"] += len(packet)

        if src_port is not None:
            flow["src_ports"].add(src_port)

        if dst_port is not None:
            flow["dst_ports"].add(dst_port)

        flow["dst_ips"].add(dst_ip)

        packet_time = float(packet.time)

        if flow["first_time"] is None:
            flow["first_time"] = packet_time

        flow["last_time"] = packet_time

        # TCP flag analysis
        if packet.haslayer(TCP):

            flags = int(packet[TCP].flags)

            # SYN flag
            if flags & 0x02:
                flow["syn_count"] += 1

            # ACK flag
            if flags & 0x10:
                flow["ack_count"] += 1

            # RST flag
            if flags & 0x04:
                flow["rst_count"] += 1

    threats = []

    # --------------------------------------------------
    # Threat detection
    # --------------------------------------------------

    for key, flow in flows.items():

        src_ip, dst_ip, protocol = key

        if flow["first_time"] is not None:

            duration = (
                flow["last_time"] -
                flow["first_time"]
            )

        else:
            duration = 0

        if duration > 0:

            packets_per_second = (
                flow["packet_count"] / duration
            )

        else:

            packets_per_second = flow["packet_count"]

        # ----------------------------------------------
        # Port Scan Detection
        # ----------------------------------------------

        if len(flow["dst_ports"]) >= 10:

            threats.append({

                "threat_type": "Port Scan",
                "severity": "High",
                "risk_score": 90,
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "protocol": protocol,
                "packet_count": flow["packet_count"],

                "description": (
                    f"Multiple destination ports contacted: "
                    f"{len(flow['dst_ports'])}"
                ),

                "is_simulated": False

            })

        # ----------------------------------------------
        # SYN Flood Detection
        # ----------------------------------------------

        if (
            flow["syn_count"] >= 50
            and flow["ack_count"] <
            flow["syn_count"] * 0.2
        ):

            threats.append({

                "threat_type": "Possible SYN Flood",
                "severity": "High",
                "risk_score": 95,
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "protocol": "TCP",
                "packet_count": flow["packet_count"],

                "description": (
                    f"High SYN count: "
                    f"{flow['syn_count']} "
                    f"with low ACK response: "
                    f"{flow['ack_count']}"
                ),

                "is_simulated": False

            })

        # ----------------------------------------------
        # UDP Flood Detection
        # ----------------------------------------------

        if (
            protocol == 17
            and flow["packet_count"] >= 100
        ):

            threats.append({

                "threat_type": "Possible UDP Flood",
                "severity": "High",
                "risk_score": 90,
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "protocol": "UDP",
                "packet_count": flow["packet_count"],

                "description": (
                    f"High UDP packet volume: "
                    f"{flow['packet_count']} packets"
                ),

                "is_simulated": False

            })

        # ----------------------------------------------
        # High Traffic Rate Detection
        # ----------------------------------------------

        if packets_per_second >= 100:

            threats.append({

                "threat_type": "Abnormally High Traffic Rate",
                "severity": "Medium",
                "risk_score": 70,
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "protocol": protocol,
                "packet_count": flow["packet_count"],

                "description": (
                    f"Traffic rate: "
                    f"{packets_per_second:.2f} "
                    f"packets/second"
                ),

                "is_simulated": False

            })

    return {

        "capture_mode": "pcap_dataset",
        "file_name": file_path,
        "total_packets": len(packets),
        "total_flows": len(flows),
        "total_threats": len(threats),
        "threats": threats,
        "status": "completed"

    }


# --------------------------------------------------
# Main program
# --------------------------------------------------

if __name__ == "__main__":

    normal_file = create_normal_dataset()

    if normal_file is not None:

        result = analyze_pcap(normal_file)

        print("\nDataset Analysis Result")
        print("-----------------------")

        print(
            "Total packets:",
            result["total_packets"]
        )

        print(
            "Total flows:",
            result["total_flows"]
        )

        print(
            "Total threats:",
            result["total_threats"]
        )

        for threat in result["threats"]:

            print("\nThreat:", threat["threat_type"])
            print("Severity:", threat["severity"])
            print("Risk score:", threat["risk_score"])
            print("Description:", threat["description"])
            