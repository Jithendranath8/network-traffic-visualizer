#!/usr/bin/env python3
"""
Create a test PCAP file with sample network traffic
"""
from scapy.all import *
import random
import time

def create_test_pcap(filename="test.pcap", num_packets=50):
    """
    Create a test PCAP file with various types of network traffic
    
    Args:
        filename: Output PCAP filename
        num_packets: Number of packets to generate
    """
    print(f"📦 Creating test PCAP file: {filename}")
    print(f"📊 Generating {num_packets} packets...")
    
    packets = []
    base_time = time.time()
    
    # Generate various types of packets
    for i in range(num_packets):
        # Vary packet types
        packet_type = i % 5
        
        if packet_type == 0:
            # TCP SYN packet
            pkt = IP(src=f"192.168.1.{random.randint(1, 254)}", 
                     dst=f"10.0.0.{random.randint(1, 254)}") / \
                 TCP(sport=random.randint(1024, 65535), 
                     dport=80, 
                     flags="S",
                     seq=random.randint(1000, 999999))
            packets.append(pkt)
            
        elif packet_type == 1:
            # TCP ACK packet
            pkt = IP(src=f"10.0.0.{random.randint(1, 254)}", 
                     dst=f"192.168.1.{random.randint(1, 254)}") / \
                 TCP(sport=80, 
                     dport=random.randint(1024, 65535), 
                     flags="A",
                     seq=random.randint(1000, 999999),
                     ack=random.randint(1000, 999999))
            packets.append(pkt)
            
        elif packet_type == 2:
            # UDP packet
            pkt = IP(src=f"172.16.0.{random.randint(1, 254)}", 
                     dst=f"8.8.8.{random.randint(1, 8)}") / \
                 UDP(sport=random.randint(1024, 65535), 
                     dport=53) / \
                 Raw(b"DNS query data")
            packets.append(pkt)
            
        elif packet_type == 3:
            # ICMP ping request
            pkt = IP(src=f"192.168.1.{random.randint(1, 254)}", 
                     dst=f"1.1.1.{random.randint(1, 4)}") / \
                 ICMP(type=8, code=0) / \
                 Raw(b"ping data")
            packets.append(pkt)
            
        else:
            # TCP with data
            pkt = IP(src=f"10.0.0.{random.randint(1, 254)}", 
                     dst=f"192.168.1.{random.randint(1, 254)}") / \
                 TCP(sport=random.randint(1024, 65535), 
                     dport=443, 
                     flags="PA",
                     seq=random.randint(1000, 999999)) / \
                 Raw(b"HTTP/1.1 GET /test\r\nHost: example.com\r\n\r\n")
            packets.append(pkt)
    
    # Set timestamps with small delays between packets
    for i, pkt in enumerate(packets):
        pkt.time = base_time + (i * 0.1)  # 0.1 second between packets
    
    # Write to PCAP file
    try:
        wrpcap(filename, packets)
        file_size = os.path.getsize(filename)
        print(f"✅ Successfully created {filename}")
        print(f"📁 File size: {file_size / 1024:.2f} KB")
        print(f"📦 Packets: {len(packets)}")
        print(f"\n💡 You can now upload it using:")
        print(f"   python3 test_pcap_upload.py {filename}")
        return True
    except Exception as e:
        print(f"❌ Error creating PCAP file: {e}")
        return False

if __name__ == '__main__':
    import sys
    import os
    
    filename = sys.argv[1] if len(sys.argv) > 1 else "test.pcap"
    num_packets = int(sys.argv[2]) if len(sys.argv) > 2 else 50
    
    # Check if Scapy is available
    try:
        from scapy.all import *
    except ImportError:
        print("❌ Error: Scapy is not installed")
        print("   Install it with: pip install scapy")
        sys.exit(1)
    
    success = create_test_pcap(filename, num_packets)
    sys.exit(0 if success else 1)
