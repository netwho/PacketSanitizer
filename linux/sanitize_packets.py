#!/usr/bin/env python3
"""
PacketSanitizer - Sanitize PCAP/PCAPNG files for safe sharing

This script sanitizes packet capture files by:
- Replacing IP addresses with anonymized versions (maintaining conversation flows)
- Replacing MAC addresses with anonymized versions
- Removing DHCP data
- Replacing payload data (UDP/TCP payloads) with sanitized pattern (0x5341 = "SA" for "Sanitized")
- Preserving packet structure and size for analysis

Modes:
- all_payload: Sanitize all payloads (no IP/MAC anonymization)
- cleartext_payload: Only sanitize clear text protocol payloads (HTTP, FTP, Telnet, SMTP, POP3, IMAP, DNS)
- payload_and_addresses: Sanitize all payloads AND anonymize IP/MAC addresses

Usage:
    python3 sanitize_packets.py <mode> <input_file> <output_file>
"""

import sys
import os
from collections import defaultdict
from scapy.all import rdpcap, wrpcap, IP, IPv6, ARP, DHCP, UDP, TCP, Ether, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP
from scapy.packet import Raw
from scapy.utils import checksum

# Try to import IGMP - it may not be available in all Scapy versions
try:
    from scapy.layers.inet import IGMP
except ImportError:
    try:
        from scapy.all import IGMP
    except ImportError:
        # IGMP not available - we'll handle it differently
        IGMP = None

# IP address mapping (maintains conversation flows)
ip_mapping = {}
ip_counter = 1
base_ip = "10.0.0.0"  # Base network for anonymization

# MAC address mapping
mac_mapping = {}
mac_counter = 1

def anonymize_ip(ip_str):
    """Anonymize IP address while maintaining conversation flows"""
    global ip_mapping, ip_counter
    
    if ip_str in ip_mapping:
        return ip_mapping[ip_str]
    
    # Generate new IP in 10.0.0.0/8 range
    new_ip = f"10.0.{ip_counter // 256}.{ip_counter % 256}"
    ip_mapping[ip_str] = new_ip
    ip_counter += 1
    
    return new_ip

def anonymize_mac(mac_str):
    """Anonymize MAC address while maintaining device identity"""
    global mac_mapping, mac_counter
    
    if mac_str in mac_mapping:
        return mac_mapping[mac_str]
    
    # Generate new MAC: 02:00:00:00:00:XX (locally administered)
    new_mac = f"02:00:00:00:00:{mac_counter:02x}"
    mac_mapping[mac_str] = new_mac
    mac_counter += 1
    
    return new_mac

def is_cleartext_protocol(packet):
    """Check if packet contains clear text protocol data"""
    # Common clear text protocol ports
    cleartext_ports = {
        # HTTP
        80, 8080, 8000, 8008, 8888,
        # FTP
        21, 20,
        # Telnet
        23,
        # SMTP
        25, 587,
        # POP3
        110, 995,
        # IMAP
        143, 993,
        # DNS
        53
    }
    
    # Check TCP ports
    if packet.haslayer(TCP):
        tcp = packet[TCP]
        if tcp.sport in cleartext_ports or tcp.dport in cleartext_ports:
            return True
        
        # Check for HTTP in payload (common ports or any port with HTTP-like data)
        if packet.haslayer(Raw):
            raw = packet[Raw]
            payload = raw.load
            # Check for HTTP methods
            if b"GET " in payload or b"POST " in payload or b"PUT " in payload or \
               b"DELETE " in payload or b"HEAD " in payload or b"OPTIONS " in payload:
                return True
            # Check for HTTP response
            if payload.startswith(b"HTTP/1.") or payload.startswith(b"HTTP/2"):
                return True
            # Check for FTP commands
            if payload.startswith(b"USER ") or payload.startswith(b"PASS ") or \
               payload.startswith(b"RETR ") or payload.startswith(b"STOR "):
                return True
            # Check for SMTP commands
            if payload.startswith(b"EHLO ") or payload.startswith(b"HELO ") or \
               payload.startswith(b"MAIL FROM:") or payload.startswith(b"RCPT TO:"):
                return True
            # Check for POP3 commands
            if payload.startswith(b"USER ") or payload.startswith(b"PASS ") or \
               payload.startswith(b"RETR ") or payload.startswith(b"DELE "):
                return True
            # Check for IMAP commands
            if payload.startswith(b"LOGIN ") or payload.startswith(b"SELECT ") or \
               payload.startswith(b"FETCH "):
                return True
    
    # Check UDP ports (DNS)
    if packet.haslayer(UDP):
        udp = packet[UDP]
        if udp.sport == 53 or udp.dport == 53:
            return True
    
    return False

def sanitize_packet(packet, mode="payload_and_addresses"):
    """Sanitize a single packet"""
    # Start with a new packet
    sanitized = None
    
    # Handle Ethernet layer
    if packet.haslayer(Ether):
        eth = packet[Ether]
        # Only anonymize MACs if mode is payload_and_addresses
        if mode == "payload_and_addresses":
            new_src = anonymize_mac(eth.src)
            new_dst = anonymize_mac(eth.dst)
            sanitized = Ether(src=new_src, dst=new_dst, type=eth.type)
        else:
            sanitized = Ether(src=eth.src, dst=eth.dst, type=eth.type)
    else:
        # If no Ethernet layer, create one (some capture formats)
        sanitized = Ether()
    
    # Handle ARP packets - remove sensitive data
    if packet.haslayer(ARP):
        arp = packet[ARP]
        # Only anonymize ARP data if mode is payload_and_addresses
        if mode == "payload_and_addresses":
            new_psrc = anonymize_ip(arp.psrc)
            new_pdst = anonymize_ip(arp.pdst) if arp.pdst != "0.0.0.0" else "0.0.0.0"
            new_hwsrc = anonymize_mac(arp.hwsrc)
            new_hwdst = anonymize_mac(arp.hwdst) if arp.hwdst != "00:00:00:00:00:00" else "00:00:00:00:00:00"
        else:
            new_psrc = arp.psrc
            new_pdst = arp.pdst
            new_hwsrc = arp.hwsrc
            new_hwdst = arp.hwdst
        
        arp_layer = ARP(
            op=arp.op,
            psrc=new_psrc,
            pdst=new_pdst,
            hwsrc=new_hwsrc,
            hwdst=new_hwdst
        )
        if sanitized:
            sanitized = sanitized / arp_layer
        else:
            sanitized = arp_layer
        return sanitized
    
    # Handle IP layer
    if packet.haslayer(IP):
        ip = packet[IP]
        
        # Check if this is an IGMP packet - if so, leave it completely untouched
        if ip.proto == 2:  # IGMP protocol number
            # Return the entire packet as-is for IGMP packets
            return packet
        
        # Only anonymize IPs if mode is payload_and_addresses
        if mode == "payload_and_addresses":
            new_src = anonymize_ip(ip.src)
            new_dst = anonymize_ip(ip.dst)
        else:
            new_src = ip.src
            new_dst = ip.dst
        
        # Build IP layer - don't set len or chksum, Scapy will recalculate
        ip_layer = IP(
            src=new_src,
            dst=new_dst,
            version=ip.version,
            ihl=ip.ihl,
            tos=ip.tos,
            id=ip.id,
            flags=ip.flags,
            frag=ip.frag,
            ttl=ip.ttl,
            proto=ip.proto
        )
        # len and chksum will be automatically calculated by Scapy
        
        if sanitized:
            sanitized = sanitized / ip_layer
        else:
            sanitized = ip_layer
        
        # Handle TCP - replace payload with sanitized pattern
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            # Preserve TCP options by copying the options field
            tcp_options = tcp.options if hasattr(tcp, 'options') and tcp.options else []
            
            tcp_layer = TCP(
                sport=tcp.sport,
                dport=tcp.dport,
                seq=tcp.seq,
                ack=tcp.ack,
                dataofs=tcp.dataofs,
                reserved=tcp.reserved,
                flags=tcp.flags,
                window=tcp.window,
                urgptr=tcp.urgptr,
                options=tcp_options  # Preserve TCP options
            )
            # Don't set chksum - let Scapy recalculate
            sanitized = sanitized / tcp_layer
            
            # Replace payload with sanitized pattern if it exists
            # Check if we should sanitize this payload based on mode
            should_sanitize_payload = False
            if mode == "all_payload":
                should_sanitize_payload = True
            elif mode == "cleartext_payload":
                should_sanitize_payload = is_cleartext_protocol(packet)
            elif mode == "payload_and_addresses":
                should_sanitize_payload = True
            
            if should_sanitize_payload and packet.haslayer(Raw):
                raw = packet[Raw]
                payload_len = len(raw.load)
                # Use 0xBADCODE pattern (repeated to match original payload size)
                pattern = b'\x53\x41'  # "SA" for "Sanitized" (0x53='S', 0x41='A')
                sanitized_payload = (pattern * ((payload_len // len(pattern)) + 1))[:payload_len]
                sanitized = sanitized / Raw(load=sanitized_payload)
            elif packet.haslayer(Raw):
                # Keep original payload if not sanitizing
                sanitized = sanitized / packet[Raw]
        
        # Handle UDP - replace payload with sanitized pattern
        elif packet.haslayer(UDP):
            udp = packet[UDP]
            udp_layer = UDP(
                sport=udp.sport,
                dport=udp.dport
            )
            # Don't set len or chksum - let Scapy recalculate
            sanitized = sanitized / udp_layer
            
            # Replace payload with sanitized pattern if it exists
            # Check if we should sanitize this payload based on mode
            should_sanitize_payload = False
            if mode == "all_payload":
                should_sanitize_payload = True
            elif mode == "cleartext_payload":
                should_sanitize_payload = is_cleartext_protocol(packet)
            elif mode == "payload_and_addresses":
                should_sanitize_payload = True
            
            if should_sanitize_payload and packet.haslayer(Raw):
                raw = packet[Raw]
                payload_len = len(raw.load)
                # Use 0xBADCODE pattern (repeated to match original payload size)
                pattern = b'\x53\x41'  # "SA" for "Sanitized" (0x53='S', 0x41='A')
                sanitized_payload = (pattern * ((payload_len // len(pattern)) + 1))[:payload_len]
                sanitized = sanitized / Raw(load=sanitized_payload)
            elif packet.haslayer(Raw):
                # Keep original payload if not sanitizing
                sanitized = sanitized / packet[Raw]
        
        # Remove DHCP layer completely
        if packet.haslayer(DHCP):
            # Don't add DHCP layer to sanitized packet
            pass
        
        # Handle ICMP - preserve structure but sanitize payload
        if packet.haslayer(ICMP):
            icmp = packet[ICMP]
            # Build ICMP layer with all available fields
            icmp_fields = {
                'type': icmp.type,
                'code': icmp.code
            }
            # Add optional fields if they exist
            if hasattr(icmp, 'chksum'): icmp_fields['chksum'] = icmp.chksum
            if hasattr(icmp, 'id'): icmp_fields['id'] = icmp.id
            if hasattr(icmp, 'seq'): icmp_fields['seq'] = icmp.seq
            if hasattr(icmp, 'gw'): icmp_fields['gw'] = icmp.gw
            if hasattr(icmp, 'ptr'): icmp_fields['ptr'] = icmp.ptr
            if hasattr(icmp, 'ts_ori'): icmp_fields['ts_ori'] = icmp.ts_ori
            if hasattr(icmp, 'ts_rx'): icmp_fields['ts_rx'] = icmp.ts_rx
            if hasattr(icmp, 'ts_tx'): icmp_fields['ts_tx'] = icmp.ts_tx
            
            icmp_layer = ICMP(**icmp_fields)
            sanitized = sanitized / icmp_layer
            
            # Replace ICMP payload if it exists
            if packet.haslayer(Raw):
                raw = packet[Raw]
                payload_len = len(raw.load)
                pattern = b'\x53\x41'  # "SA" for "Sanitized" (0x53='S', 0x41='A')
                sanitized_payload = (pattern * ((payload_len // len(pattern)) + 1))[:payload_len]
                sanitized = sanitized / Raw(load=sanitized_payload)
        
        # IGMP packets are already handled above and returned early
        # This section should not be reached for IGMP packets
        
        # Handle any remaining Raw payload (for other protocols)
        elif packet.haslayer(Raw) and not sanitized.haslayer(Raw):
            raw = packet[Raw]
            payload_len = len(raw.load)
            # Use printable ASCII pattern "SA" for "Sanitized" (0x53='S', 0x41='A')
            pattern = b'\x53\x41'
            sanitized_payload = (pattern * ((payload_len // len(pattern)) + 1))[:payload_len]
            sanitized = sanitized / Raw(load=sanitized_payload)
        
        return sanitized
    
    # Handle IPv6
    if packet.haslayer(IPv6):
        ipv6 = packet[IPv6]
        # Only anonymize IPv6 addresses if mode is payload_and_addresses
        if mode == "payload_and_addresses":
            new_src = anonymize_ip(ipv6.src)
            new_dst = anonymize_ip(ipv6.dst)
        else:
            new_src = ipv6.src
            new_dst = ipv6.dst
        
        # Build IPv6 layer (let Scapy recalculate plen)
        ipv6_layer = IPv6(
            src=new_src,
            dst=new_dst,
            version=ipv6.version,
            tc=ipv6.tc,
            fl=ipv6.fl,
            nh=ipv6.nh,
            hlim=ipv6.hlim
        )
        # Don't set plen - let Scapy recalculate
        
        if sanitized:
            sanitized = sanitized / ipv6_layer
        else:
            sanitized = ipv6_layer
        
        # Handle TCP/UDP in IPv6 - replace payload with sanitized pattern
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            # Preserve TCP options by copying the options field
            tcp_options = tcp.options if hasattr(tcp, 'options') and tcp.options else []
            
            tcp_layer = TCP(
                sport=tcp.sport,
                dport=tcp.dport,
                seq=tcp.seq,
                ack=tcp.ack,
                dataofs=tcp.dataofs,
                reserved=tcp.reserved,
                flags=tcp.flags,
                window=tcp.window,
                urgptr=tcp.urgptr,
                options=tcp_options  # Preserve TCP options
            )
            # Don't set chksum - let Scapy recalculate
            sanitized = sanitized / tcp_layer
            
            # Replace payload with sanitized pattern if it exists
            # Check if we should sanitize this payload based on mode
            should_sanitize_payload = False
            if mode == "all_payload":
                should_sanitize_payload = True
            elif mode == "cleartext_payload":
                should_sanitize_payload = is_cleartext_protocol(packet)
            elif mode == "payload_and_addresses":
                should_sanitize_payload = True
            
            if should_sanitize_payload and packet.haslayer(Raw):
                raw = packet[Raw]
                payload_len = len(raw.load)
                # Use 0xBADCODE pattern (repeated to match original payload size)
                pattern = b'\x53\x41'  # "SA" for "Sanitized" (0x53='S', 0x41='A')
                sanitized_payload = (pattern * ((payload_len // len(pattern)) + 1))[:payload_len]
                sanitized = sanitized / Raw(load=sanitized_payload)
            elif packet.haslayer(Raw):
                # Keep original payload if not sanitizing
                sanitized = sanitized / packet[Raw]
        elif packet.haslayer(UDP):
            udp = packet[UDP]
            udp_layer = UDP(
                sport=udp.sport,
                dport=udp.dport
            )
            # Don't set len or chksum - let Scapy recalculate
            sanitized = sanitized / udp_layer
            
            # Replace payload with sanitized pattern if it exists
            # Check if we should sanitize this payload based on mode
            should_sanitize_payload = False
            if mode == "all_payload":
                should_sanitize_payload = True
            elif mode == "cleartext_payload":
                should_sanitize_payload = is_cleartext_protocol(packet)
            elif mode == "payload_and_addresses":
                should_sanitize_payload = True
            
            if should_sanitize_payload and packet.haslayer(Raw):
                raw = packet[Raw]
                payload_len = len(raw.load)
                # Use 0xBADCODE pattern (repeated to match original payload size)
                pattern = b'\x53\x41'  # "SA" for "Sanitized" (0x53='S', 0x41='A')
                sanitized_payload = (pattern * ((payload_len // len(pattern)) + 1))[:payload_len]
                sanitized = sanitized / Raw(load=sanitized_payload)
            elif packet.haslayer(Raw):
                # Keep original payload if not sanitizing
                sanitized = sanitized / packet[Raw]
        
        # Handle ICMP in IPv6 - preserve structure but sanitize payload
        if packet.haslayer(ICMP):
            icmp = packet[ICMP]
            # Build ICMP layer with all available fields
            icmp_fields = {
                'type': icmp.type,
                'code': icmp.code
            }
            # Add optional fields if they exist
            if hasattr(icmp, 'chksum'): icmp_fields['chksum'] = icmp.chksum
            if hasattr(icmp, 'id'): icmp_fields['id'] = icmp.id
            if hasattr(icmp, 'seq'): icmp_fields['seq'] = icmp.seq
            if hasattr(icmp, 'gw'): icmp_fields['gw'] = icmp.gw
            if hasattr(icmp, 'ptr'): icmp_fields['ptr'] = icmp.ptr
            if hasattr(icmp, 'ts_ori'): icmp_fields['ts_ori'] = icmp.ts_ori
            if hasattr(icmp, 'ts_rx'): icmp_fields['ts_rx'] = icmp.ts_rx
            if hasattr(icmp, 'ts_tx'): icmp_fields['ts_tx'] = icmp.ts_tx
            
            icmp_layer = ICMP(**icmp_fields)
            sanitized = sanitized / icmp_layer
            
            # Replace ICMP payload if it exists
            # Check if we should sanitize this payload based on mode
            should_sanitize_payload = False
            if mode == "all_payload":
                should_sanitize_payload = True
            elif mode == "cleartext_payload":
                should_sanitize_payload = False  # ICMP is not a clear text protocol
            elif mode == "payload_and_addresses":
                should_sanitize_payload = True
            
            if should_sanitize_payload and packet.haslayer(Raw):
                raw = packet[Raw]
                payload_len = len(raw.load)
                pattern = b'\x53\x41'  # "SA" for "Sanitized" (0x53='S', 0x41='A')
                sanitized_payload = (pattern * ((payload_len // len(pattern)) + 1))[:payload_len]
                sanitized = sanitized / Raw(load=sanitized_payload)
            elif packet.haslayer(Raw):
                # Keep original payload if not sanitizing
                sanitized = sanitized / packet[Raw]
        
        # Handle IGMP in IPv6 - leave IGMP packets completely untouched
        if packet.haslayer(IPv6) and packet[IPv6].nh == 2:  # IGMP protocol number
            # Return the entire packet as-is for IGMP packets
            return packet
        
        # Handle any remaining Raw payload (for other protocols)
        elif packet.haslayer(Raw) and not sanitized.haslayer(Raw):
            # Check if we should sanitize this payload based on mode
            should_sanitize_payload = False
            if mode == "all_payload":
                should_sanitize_payload = True
            elif mode == "cleartext_payload":
                should_sanitize_payload = is_cleartext_protocol(packet)
            elif mode == "payload_and_addresses":
                should_sanitize_payload = True
            
            if should_sanitize_payload:
                raw = packet[Raw]
                payload_len = len(raw.load)
                # Use printable ASCII pattern "SA" for "Sanitized" (0x53='S', 0x41='A')
                pattern = b'\x53\x41'
                sanitized_payload = (pattern * ((payload_len // len(pattern)) + 1))[:payload_len]
                sanitized = sanitized / Raw(load=sanitized_payload)
            else:
                # Keep original payload if not sanitizing
                sanitized = sanitized / packet[Raw]
        
        return sanitized
    
    # For other packet types, return as-is (or minimal sanitization)
    return sanitized if sanitized else packet

def sanitize_file(input_file, output_file, mode="payload_and_addresses"):
    """Sanitize a PCAP/PCAPNG file"""
    print(f"Reading packets from: {input_file}")
    print(f"Sanitization mode: {mode}")
    
    try:
        packets = rdpcap(input_file)
        print(f"Loaded {len(packets)} packets")
    except Exception as e:
        print(f"Error reading file: {e}", file=sys.stderr)
        sys.exit(1)
    
    sanitized_packets = []
    
    print("Sanitizing packets...")
    for i, packet in enumerate(packets):
        try:
            sanitized = sanitize_packet(packet, mode)
            if sanitized:
                sanitized_packets.append(sanitized)
        except Exception as e:
            print(f"Warning: Error sanitizing packet {i}: {e}", file=sys.stderr)
            continue
    
    print(f"Writing {len(sanitized_packets)} sanitized packets to: {output_file}")
    
    try:
        # Write packets - Scapy automatically recalculates checksums when writing
        # Rebuild packets to force checksum recalculation, but skip IGMP packets
        final_packets = []
        for pkt in sanitized_packets:
            # Check if this is an IGMP packet - if so, don't rebuild it
            is_igmp = False
            if pkt.haslayer(IP) and pkt[IP].proto == 2:
                is_igmp = True
            elif pkt.haslayer(IPv6) and pkt[IPv6].nh == 2:
                is_igmp = True
            
            if is_igmp:
                # IGMP packets are left completely untouched - use as-is
                final_packets.append(pkt)
            else:
                # For other packets, convert to bytes and back to force Scapy to recalculate all fields
                pkt_bytes = bytes(pkt)
                # Reconstruct from bytes - this forces Scapy to recalculate checksums
                try:
                    rebuilt = Ether(pkt_bytes)
                    final_packets.append(rebuilt)
                except:
                    # If reconstruction fails, use original
                    final_packets.append(pkt)
        
        wrpcap(output_file, final_packets)
        print("Sanitization complete!")
        print(f"\nStatistics:")
        print(f"  Original packets: {len(packets)}")
        print(f"  Sanitized packets: {len(sanitized_packets)}")
        print(f"  Unique IPs anonymized: {len(ip_mapping)}")
        print(f"  Unique MACs anonymized: {len(mac_mapping)}")
    except Exception as e:
        print(f"Error writing file: {e}", file=sys.stderr)
        sys.exit(1)

def main():
    if len(sys.argv) != 4:
        print("Usage: python3 sanitize_packets.py <mode> <input_file> <output_file>", file=sys.stderr)
        print("Modes:", file=sys.stderr)
        print("  all_payload - Sanitize all payloads (no IP/MAC anonymization)", file=sys.stderr)
        print("  cleartext_payload - Only sanitize clear text protocol payloads", file=sys.stderr)
        print("  payload_and_addresses - Sanitize all payloads AND anonymize IP/MAC addresses", file=sys.stderr)
        sys.exit(1)
    
    mode = sys.argv[1]
    input_file = sys.argv[2]
    output_file = sys.argv[3]
    
    # Validate mode
    valid_modes = ["all_payload", "cleartext_payload", "payload_and_addresses"]
    if mode not in valid_modes:
        print(f"Error: Invalid mode '{mode}'. Valid modes: {', '.join(valid_modes)}", file=sys.stderr)
        sys.exit(1)
    
    if not os.path.exists(input_file):
        print(f"Error: Input file not found: {input_file}", file=sys.stderr)
        sys.exit(1)
    
    sanitize_file(input_file, output_file, mode)

if __name__ == "__main__":
    main()

