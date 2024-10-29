import textwrap
from scapy.all import sniff, Ether, IP, TCP, UDP, ICMP
import time

# Helper function to format multi-line data for readability
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ' '.join(f'{byte:02x}' for byte in string)
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

# Packet processing function
def process_packet(packet, protocol_filter=None, port_filter=None):
    if Ether in packet:
        eth_proto = packet[Ether].type
        print(f"\nEthernet Frame:")
        print(f"Destination MAC: {packet[Ether].dst}, Source MAC: {packet[Ether].src}, Protocol: {eth_proto}")

        if IP in packet:
            ip_layer = packet[IP]
            proto = ip_layer.proto

            # Check protocol filter
            if protocol_filter:
                if protocol_filter == 'TCP' and TCP not in packet:
                    return
                elif protocol_filter == 'UDP' and UDP not in packet:
                    return
                elif protocol_filter == 'ICMP' and ICMP not in packet:
                    return

            print(f"IPv4 Packet: Source IP: {ip_layer.src}, Destination IP: {ip_layer.dst}, TTL: {ip_layer.ttl}")

            # ICMP
            if ICMP in packet:
                icmp_layer = packet[ICMP]
                print("ICMP Packet:")
                print(f"Type: {icmp_layer.type}, Code: {icmp_layer.code}")
                print(f"Data: {format_multi_line('\t', bytes(icmp_layer.payload))}")

            # TCP
            elif TCP in packet:
                tcp_layer = packet[TCP]
                
                # Port filtering
                if port_filter and tcp_layer.sport != port_filter and tcp_layer.dport != port_filter:
                    return

                print("TCP Segment:")
                print(f"Source Port: {tcp_layer.sport}, Destination Port: {tcp_layer.dport}")
                print(f"Sequence: {tcp_layer.seq}, Acknowledgement: {tcp_layer.ack}")
                print(f"Flags: URG: {tcp_layer.flags & 0x20}, ACK: {tcp_layer.flags & 0x10}, PSH: {tcp_layer.flags & 0x08}, "
                      f"RST: {tcp_layer.flags & 0x04}, SYN: {tcp_layer.flags & 0x02}, FIN: {tcp_layer.flags & 0x01}")
                print(f"Data: {format_multi_line('\t', bytes(tcp_layer.payload))}")

            # UDP
            elif UDP in packet:
                udp_layer = packet[UDP]
                
                # Port filtering
                if port_filter and udp_layer.sport != port_filter and udp_layer.dport != port_filter:
                    return

                print("UDP Segment:")
                print(f"Source Port: {udp_layer.sport}, Destination Port: {udp_layer.dport}, Length: {udp_layer.len}")
                print(f"Data: {format_multi_line('\t', bytes(udp_layer.payload))}")

            # Other protocols
            else:
                print(f"Other Protocol: {proto}")
                print(f"Data: {format_multi_line('\t', bytes(packet[IP].payload))}")

# Sniff packets
def sniff_packets(protocol_filter=None, port_filter=None, packet_limit=None, time_limit=None):
    # Define capture filter based on provided filters
    filter_str = "ip"
    if protocol_filter:
        filter_str = protocol_filter.lower()

    if port_filter:
        filter_str += f" port {port_filter}"

    # Define callback function with packet limit and time limit
    start_time = time.time()
    packet_count = 0

    def packet_callback(packet):
        nonlocal packet_count
        if packet_limit and packet_count >= packet_limit:
            return False  # Stop sniffing
        if time_limit and time.time() - start_time > time_limit:
            return False  # Stop sniffing

        process_packet(packet, protocol_filter, port_filter)
        packet_count += 1

    # Start sniffing
    sniff(filter=filter_str, prn=packet_callback, store=False, stop_filter=lambda p: packet_count >= packet_limit or (time_limit and time.time() - start_time > time_limit))

# Usage
if __name__ == "__main__":
    protocol = input("Enter protocol filter (TCP/UDP/ICMP or leave blank for all): ").upper() or None
    port = input("Enter port filter (e.g., 80 or leave blank for all): ")
    port = int(port) if port else None
    packet_limit = input("Enter packet limit (or leave blank for no limit): ")
    packet_limit = int(packet_limit) if packet_limit else None
    time_limit = input("Enter time limit in seconds (or leave blank for no limit): ")
    time_limit = int(time_limit) if time_limit else None

    sniff_packets(protocol_filter=protocol, port_filter=port, packet_limit=packet_limit, time_limit=time_limit)
