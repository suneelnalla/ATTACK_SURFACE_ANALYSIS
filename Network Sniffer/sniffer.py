import socket
import struct
import textwrap
import time

# Helper function to format multi-line data for readability
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ' '.join(f'{byte:02x}' for byte in string)
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

# Unpack Ethernet frame
def unpack_ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    dest_mac = get_mac_addr(dest_mac)
    src_mac = get_mac_addr(src_mac)
    proto = socket.htons(proto)
    return dest_mac, src_mac, proto, data[14:]

# Format MAC address
def get_mac_addr(bytes_addr):
    return ':'.join(map('{:02x}'.format, bytes_addr))

# Unpack IPv4 packet
def unpack_ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    src = ipv4(src)
    target = ipv4(target)
    return version, header_length, ttl, proto, src, target, data[header_length:]

# Format IPv4 address
def ipv4(addr):
    return '.'.join(map(str, addr))

# Unpack ICMP packet
def unpack_icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

# Unpack TCP segment
def unpack_tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgement, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

# Unpack UDP segment
def unpack_udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]

# Main function to sniff packets with filtering and limits
def sniff_packets(protocol_filter=None, port_filter=None, packet_limit=None, time_limit=None):
    # Create raw socket to capture all traffic
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    
    start_time = time.time()
    packet_count = 0

    while True:
        # Stop after capturing the specified number of packets
        if packet_limit and packet_count >= packet_limit:
            print(f"\nPacket limit of {packet_limit} reached.")
            break

        # Stop after time limit
        if time_limit and time.time() - start_time > time_limit:
            print(f"\nTime limit of {time_limit} seconds reached.")
            break

        raw_data, addr = s.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = unpack_ethernet_frame(raw_data)

        # Filter by protocol (if specified)
        if protocol_filter and eth_proto != 8:
            continue  # Skip non-IPv4 packets

        # IPv4
        if eth_proto == 8:
            version, header_length, ttl, proto, src, target, data = unpack_ipv4_packet(data)

            # ICMP Filtering
            if protocol_filter == 'ICMP' and proto != 1:
                continue
            # TCP Filtering
            elif protocol_filter == 'TCP' and proto != 6:
                continue
            # UDP Filtering
            elif protocol_filter == 'UDP' and proto != 17:
                continue

            # Packet Count increment
            packet_count += 1

            print(f'\nPacket {packet_count}: Ethernet Frame:')
            print(f'Destination MAC: {dest_mac}, Source MAC: {src_mac}, Protocol: {eth_proto}')

            # ICMP
            if proto == 1:
                icmp_type, code, checksum, data = unpack_icmp_packet(data)
                print('ICMP Packet:')
                print(f'Type: {icmp_type}, Code: {code}, Checksum: {checksum}')
                print(f'Data: {format_multi_line("\t", data)}')

            # TCP
            elif proto == 6:
                src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data = unpack_tcp_segment(data)

                # Filter by port (if specified)
                if port_filter and src_port != port_filter and dest_port != port_filter:
                    continue

                print('TCP Segment:')
                print(f'Source Port: {src_port}, Destination Port: {dest_port}')
                print(f'Sequence: {sequence}, Acknowledgement: {acknowledgement}')
                print(f'Flags: URG: {flag_urg}, ACK: {flag_ack}, PSH: {flag_psh}, RST: {flag_rst}, SYN: {flag_syn}, FIN: {flag_fin}')
                print(f'Data: {format_multi_line("\t", data)}')

            # UDP
            elif proto == 17:
                src_port, dest_port, length, data = unpack_udp_segment(data)

                # Filter by port (if specified)
                if port_filter and src_port != port_filter and dest_port != port_filter:
                    continue

                print('UDP Segment:')
                print(f'Source Port: {src_port}, Destination Port: {dest_port}, Length: {length}')
                print(f'Data: {format_multi_line("\t", data)}')

            # Other IPv4 protocols
            else:
                print(f'Other IPv4 Protocol: {proto}')
                print(f'Data: {format_multi_line("\t", data)}')

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
