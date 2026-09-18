from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import defaultdict
from datetime import datetime
import json
import os
import joblib


# ============================================================
# Load trained AI model
# ============================================================

MODEL_FILE = os.path.join(
    "models",
    "threat_model.pkl"
)

AI_MODEL = None

if os.path.exists(MODEL_FILE):
    try:
        AI_MODEL = joblib.load(MODEL_FILE)
        print("AI model loaded successfully.")
    except Exception as error:
        print("Could not load AI model:", error)
else:
    print("AI model not found:", MODEL_FILE)


# ============================================================
# Detection thresholds
# ============================================================

UDP_PACKET_THRESHOLD = 20
PORT_SCAN_THRESHOLD = 3
DESTINATION_DIVERSITY_THRESHOLD = 10
SOURCE_PACKET_THRESHOLD = 100
SYN_PACKET_THRESHOLD = 50
ICMP_PACKET_THRESHOLD = 100


# ============================================================
# Suspicious ports
# ============================================================

SUSPICIOUS_PORTS = {
    21: "FTP",
    23: "Telnet",
    139: "NetBIOS",
    445: "SMB",
    3389: "RDP",
    4444: "Remote Shell"
}


# ============================================================
# Protocol conversion
# ============================================================

def protocol_to_number(protocol):
    protocol = str(protocol).upper().strip()

    if protocol == "TCP":
        return 6

    if protocol == "UDP":
        return 17

    if protocol == "ICMP":
        return 1

    return 0


# ============================================================
# AI anomaly prediction
# ============================================================

def predict_ai_threat(
    src_port,
    dst_port,
    protocol,
    packet_count,
    total_bytes
):
    """
    Detect unusual network-flow behavior using the trained
    Isolation Forest model.

    The AI result is an anomaly indicator, not a confirmed
    attack classification.
    """

    if AI_MODEL is None:
        return {
            "ai_prediction": "Unavailable",
            "ai_risk_score": 0,
            "detection_method": "Rule-Based Only"
        }

    protocol_number = protocol_to_number(protocol)

    try:
        packet_count = float(packet_count)
        total_bytes = float(total_bytes)
        src_port = float(src_port)
        dst_port = float(dst_port)

        if packet_count <= 0:
            packet_count = 1

        bytes_per_packet = total_bytes / packet_count

        features = [[
            src_port,
            dst_port,
            protocol_number,
            packet_count,
            total_bytes,
            bytes_per_packet
        ]]

        prediction = AI_MODEL.predict(features)[0]

        decision_value = AI_MODEL.decision_function(
            features
        )[0]

        if prediction == -1:
            ai_prediction = "Anomaly"
        else:
            ai_prediction = "Normal"

        # This is a relative anomaly risk score,
        # not a probability or confirmed attack percentage.
        ai_risk_score = round(
            max(
                0,
                min(
                    100,
                    50 - (decision_value * 100)
                )
            ),
            2
        )

        return {
            "ai_prediction": ai_prediction,
            "ai_risk_score": ai_risk_score,
            "detection_method": "AI Detection"
        }

    except Exception as error:
        print("AI prediction error:", error)

        return {
            "ai_prediction": "Unavailable",
            "ai_risk_score": 0,
            "detection_method": "Rule-Based Only"
        }


# ============================================================
# Main live capture function
# ============================================================

def capture_live_traffic(interface=None, duration=5):
    """
    Capture and analyze real network traffic.

    This performs passive packet capture only.
    It does not scan, block, inject, or modify packets.
    """

    print("=" * 80)
    print("UniFlow Passive AI-Based Cyber-Threat Detection")
    print("Live Traffic Analysis Started")
    print("=" * 80)

    print(f"Capture duration: {duration} seconds")

    # --------------------------------------------------------
    # 1. Capture packets
    # --------------------------------------------------------

    packets = sniff(
        iface=interface,
        timeout=duration,
        store=True
    )

    print(f"Total packets captured: {len(packets)}")

    # --------------------------------------------------------
    # 2. Data structures
    # --------------------------------------------------------

    flows = defaultdict(
        lambda: {
            "packet_count": 0,
            "total_bytes": 0
        }
    )

    source_ports = defaultdict(set)
    source_destinations = defaultdict(set)
    source_packet_count = defaultdict(int)
    source_flow_keys = defaultdict(set)

    syn_count = defaultdict(int)
    udp_count = defaultdict(int)
    icmp_count = defaultdict(int)

    threats = []

    threatened_flow_keys = set()
    suspicious_port_flow_keys = set()

    # --------------------------------------------------------
    # 3. Extract flow information
    # --------------------------------------------------------

    for packet in packets:

        # Ignore non-IPv4 packets
        if IP not in packet:
            continue

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        protocol = "OTHER"
        src_port = 0
        dst_port = 0

        # ----------------------------------------------------
        # TCP
        # ----------------------------------------------------

        if TCP in packet:

            protocol = "TCP"

            src_port = int(packet[TCP].sport)
            dst_port = int(packet[TCP].dport)

            tcp_flags = str(packet[TCP].flags)

            # SYN without ACK
            if "S" in tcp_flags and "A" not in tcp_flags:
                syn_count[src_ip] += 1

            # Suspicious destination port
            if dst_port in SUSPICIOUS_PORTS:
                suspicious_port_flow_keys.add(
                    (
                        src_ip,
                        dst_ip,
                        src_port,
                        dst_port,
                        protocol
                    )
                )

        # ----------------------------------------------------
        # UDP
        # ----------------------------------------------------

        elif UDP in packet:

            protocol = "UDP"

            src_port = int(packet[UDP].sport)
            dst_port = int(packet[UDP].dport)

            udp_count[src_ip] += 1

        # ----------------------------------------------------
        # ICMP
        # ----------------------------------------------------

        elif ICMP in packet:

            protocol = "ICMP"
            icmp_count[src_ip] += 1

        # ----------------------------------------------------
        # Flow key
        # ----------------------------------------------------

        flow_key = (
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol
        )

        # ----------------------------------------------------
        # Update flow statistics
        # ----------------------------------------------------

        flows[flow_key]["packet_count"] += 1
        flows[flow_key]["total_bytes"] += len(packet)

        # ----------------------------------------------------
        # Update source statistics
        # ----------------------------------------------------

        source_packet_count[src_ip] += 1
        source_destinations[src_ip].add(dst_ip)
        source_flow_keys[src_ip].add(flow_key)

        if dst_port != 0:
            source_ports[src_ip].add(dst_port)

    # ========================================================
    # 4. Rule-based threat detection
    # ========================================================

    # --------------------------------------------------------
    # Rule 1: Suspicious destination port
    # --------------------------------------------------------

    for flow_key in suspicious_port_flow_keys:

        (
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol
        ) = flow_key

        flow_data = flows[flow_key]

        threats.append({
            "timestamp": datetime.now().isoformat(),
            "threat_type": "Suspicious Port Activity",
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "source_port": src_port,
            "destination_port": dst_port,
            "protocol": protocol,
            "packet_count": flow_data["packet_count"],
            "total_bytes": flow_data["total_bytes"],
            "severity": "Medium",
            "risk_score": 60,
            "description": (
                f"Traffic was observed toward port {dst_port} "
                f"({SUSPICIOUS_PORTS[dst_port]}). "
                "This is an indicator that requires investigation."
            )
        })

        threatened_flow_keys.add(flow_key)

    # --------------------------------------------------------
    # Rule 2: High-volume UDP traffic
    # --------------------------------------------------------

    for flow_key, flow_data in flows.items():

        (
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol
        ) = flow_key

        packet_count = flow_data["packet_count"]
        total_bytes = flow_data["total_bytes"]

        if (
            protocol == "UDP"
            and packet_count >= UDP_PACKET_THRESHOLD
        ):

            threats.append({
                "timestamp": datetime.now().isoformat(),
                "threat_type": "High-Volume UDP Traffic",
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "source_port": src_port,
                "destination_port": dst_port,
                "protocol": protocol,
                "packet_count": packet_count,
                "total_bytes": total_bytes,
                "severity": "High",
                "risk_score": 90,
                "description": (
                    f"{packet_count} UDP packets were observed "
                    "in the current capture window."
                )
            })

            threatened_flow_keys.add(flow_key)

    # --------------------------------------------------------
    # Rule 3: Possible port scan
    # --------------------------------------------------------

    for src_ip, ports in source_ports.items():

        if len(ports) >= PORT_SCAN_THRESHOLD:

            threats.append({
                "timestamp": datetime.now().isoformat(),
                "threat_type": "Possible Port Scan",
                "source_ip": src_ip,
                "destination_ip": "Multiple",
                "source_port": 0,
                "destination_port": 0,
                "protocol": "TCP/UDP",
                "packet_count": source_packet_count[src_ip],
                "total_bytes": 0,
                "severity": "High",
                "risk_score": 85,
                "description": (
                    f"Source IP {src_ip} contacted "
                    f"{len(ports)} different destination ports."
                )
            })

            for flow_key in source_flow_keys[src_ip]:
                threatened_flow_keys.add(flow_key)

    # --------------------------------------------------------
    # Rule 4: High destination diversity
    # --------------------------------------------------------

    for src_ip, destinations in source_destinations.items():

        if len(destinations) >= DESTINATION_DIVERSITY_THRESHOLD:

            threats.append({
                "timestamp": datetime.now().isoformat(),
                "threat_type": "High Destination Diversity",
                "source_ip": src_ip,
                "destination_ip": "Multiple",
                "source_port": 0,
                "destination_port": 0,
                "protocol": "TCP/UDP",
                "packet_count": source_packet_count[src_ip],
                "total_bytes": 0,
                "severity": "Medium",
                "risk_score": 55,
                "description": (
                    f"Source IP {src_ip} contacted "
                    f"{len(destinations)} different destination IPs "
                    "during the capture window."
                )
            })

            for flow_key in source_flow_keys[src_ip]:
                threatened_flow_keys.add(flow_key)

    # --------------------------------------------------------
    # Rule 5: High packet volume
    # --------------------------------------------------------

    for src_ip, packet_count in source_packet_count.items():

        if packet_count >= SOURCE_PACKET_THRESHOLD:

            threats.append({
                "timestamp": datetime.now().isoformat(),
                "threat_type": "High Packet Volume",
                "source_ip": src_ip,
                "destination_ip": "Multiple",
                "source_port": 0,
                "destination_port": 0,
                "protocol": "TCP/UDP",
                "packet_count": packet_count,
                "total_bytes": 0,
                "severity": "Medium",
                "risk_score": 50,
                "description": (
                    f"Source IP {src_ip} generated "
                    f"{packet_count} packets in the capture window."
                )
            })

            for flow_key in source_flow_keys[src_ip]:
                threatened_flow_keys.add(flow_key)

    # --------------------------------------------------------
    # Rule 6: Possible SYN flood
    # --------------------------------------------------------

    for src_ip, count in syn_count.items():

        if count >= SYN_PACKET_THRESHOLD:

            threats.append({
                "timestamp": datetime.now().isoformat(),
                "threat_type": "Possible SYN Flood",
                "source_ip": src_ip,
                "destination_ip": "Multiple",
                "source_port": 0,
                "destination_port": 0,
                "protocol": "TCP",
                "packet_count": count,
                "total_bytes": 0,
                "severity": "High",
                "risk_score": 90,
                "description": (
                    f"{count} TCP SYN packets were observed "
                    f"from source IP {src_ip}."
                )
            })

            for flow_key in source_flow_keys[src_ip]:

                if flow_key[-1] == "TCP":
                    threatened_flow_keys.add(flow_key)

    # --------------------------------------------------------
    # Rule 7: Possible ICMP flood
    # --------------------------------------------------------

    for src_ip, count in icmp_count.items():

        if count >= ICMP_PACKET_THRESHOLD:

            threats.append({
                "timestamp": datetime.now().isoformat(),
                "threat_type": "Possible ICMP Flood",
                "source_ip": src_ip,
                "destination_ip": "Multiple",
                "source_port": 0,
                "destination_port": 0,
                "protocol": "ICMP",
                "packet_count": count,
                "total_bytes": 0,
                "severity": "Medium",
                "risk_score": 65,
                "description": (
                    f"{count} ICMP packets were observed "
                    f"from source IP {src_ip}."
                )
            })

            for flow_key in source_flow_keys[src_ip]:

                if flow_key[-1] == "ICMP":
                    threatened_flow_keys.add(flow_key)

    # ========================================================
    # 5. AI detection for every flow
    # ========================================================

    flow_list = []

    for flow_key, flow_data in flows.items():

        (
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol
        ) = flow_key

        ai_result = predict_ai_threat(
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            packet_count=flow_data["packet_count"],
            total_bytes=flow_data["total_bytes"]
        )

        # Mark flow as suspicious if either:
        # 1. Rule-based detection identifies it
        # 2. AI identifies it as an anomaly
        is_rule_suspicious = (
            flow_key in threatened_flow_keys
        )

        is_ai_suspicious = (
            ai_result["ai_prediction"] == "Anomaly"
        )

        is_suspicious = (
            is_rule_suspicious or is_ai_suspicious
        )

        # Add a generic AI threat record
        if is_ai_suspicious and not is_rule_suspicious:

            threats.append({
                "timestamp": datetime.now().isoformat(),
                "threat_type": "AI Anomaly",
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "source_port": src_port,
                "destination_port": dst_port,
                "protocol": protocol,
                "packet_count": flow_data["packet_count"],
                "total_bytes": flow_data["total_bytes"],
                "severity": (
                    "High"
                    if ai_result["ai_risk_score"] >= 70
                    else "Medium"
                ),
                "risk_score": ai_result["ai_risk_score"],
                "description": (
                    "The AI model identified this flow as "
                    "unusual compared with the training data."
                )
            })

        flow_list.append({
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "source_port": src_port,
            "destination_port": dst_port,
            "protocol": protocol,
            "packet_count": flow_data["packet_count"],
            "total_bytes": flow_data["total_bytes"],
            "ai_prediction": ai_result["ai_prediction"],
            "ai_risk_score": ai_result["ai_risk_score"],
            "detection_method": ai_result["detection_method"],
            "status": (
                "Suspicious"
                if is_suspicious
                else "Normal"
            )
        })

    # ========================================================
    # 6. Calculate threat statistics
    # ========================================================

    high_threats = 0
    medium_threats = 0
    low_threats = 0
    total_risk_score = 0

    for threat in threats:

        total_risk_score += threat["risk_score"]

        severity = threat["severity"].lower()

        if severity == "high":
            high_threats += 1

        elif severity == "medium":
            medium_threats += 1

        elif severity == "low":
            low_threats += 1

    if threats:
        average_risk_score = (
            total_risk_score / len(threats)
        )
    else:
        average_risk_score = 0

    # --------------------------------------------------------
    # Overall risk
    # --------------------------------------------------------

    if average_risk_score >= 70:
        overall_risk = "High"

    elif average_risk_score >= 40:
        overall_risk = "Medium"

    else:
        overall_risk = "Low"

    # ========================================================
    # 7. Flow summary
    # ========================================================

    total_flows = len(flow_list)

    suspicious_flow_count = sum(
        1
        for flow in flow_list
        if flow["status"] == "Suspicious"
    )

    normal_flow_count = max(
        total_flows - suspicious_flow_count,
        0
    )

    ai_anomaly_count = sum(
        1
        for flow in flow_list
        if flow["ai_prediction"] == "Anomaly"
    )

    # ========================================================
    # 8. Final result
    # ========================================================

    result = {
        "status": "success",
        "timestamp": datetime.now().isoformat(),
        "window_seconds": duration,

        "total_packets": len(packets),
        "total_flows": total_flows,

        "normal_flows": normal_flow_count,
        "suspicious_flows": suspicious_flow_count,
        "high_risk_flows": high_threats,

        "total_threats": len(threats),

        "high_threats": high_threats,
        "medium_threats": medium_threats,
        "low_threats": low_threats,

        "average_risk_score": round(
            average_risk_score,
            2
        ),

        "overall_risk": overall_risk,

        "ai_model_loaded": AI_MODEL is not None,
        "ai_anomalies": ai_anomaly_count,

        "threats": threats,
        "flows": flow_list
    }

    # ========================================================
    # 9. Print result
    # ========================================================

    print("\n" + "=" * 80)
    print("LIVE ANALYSIS RESULT")
    print("=" * 80)

    print(f"Packets: {result['total_packets']}")
    print(f"Flows: {result['total_flows']}")
    print(f"Normal flows: {result['normal_flows']}")
    print(f"Suspicious flows: {result['suspicious_flows']}")
    print(f"High-risk flows: {result['high_risk_flows']}")
    print(f"Threats: {result['total_threats']}")
    print(f"AI anomalies: {result['ai_anomalies']}")

    print(
        f"Average risk score: "
        f"{result['average_risk_score']}/100"
    )

    print(f"Overall risk: {result['overall_risk']}")

    print("\nThreat details:")

    if threats:

        for index, threat in enumerate(
            threats,
            start=1
        ):

            print(f"\nThreat {index}")

            print(
                f"Type: "
                f"{threat['threat_type']}"
            )

            print(
                f"Source IP: "
                f"{threat['source_ip']}"
            )

            print(
                f"Destination IP: "
                f"{threat['destination_ip']}"
            )

            print(
                f"Severity: "
                f"{threat['severity']}"
            )

            print(
                f"Risk score: "
                f"{threat['risk_score']}"
            )

            print(
                f"Description: "
                f"{threat['description']}"
            )

    else:
        print("No suspicious behavior detected.")

    return result


# ============================================================
# Standalone testing
# ============================================================

if __name__ == "__main__":

    result = capture_live_traffic(
        interface=None,
        duration=5
    )

    print("\nReturned result:")

    print(
        json.dumps(
            result,
            indent=4
        )
    )