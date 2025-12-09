#!/usr/bin/env python3
"""
Quick script to test PCAP upload functionality
"""
import requests
import sys
import os
from pathlib import Path

def upload_pcap(file_path: str, speed: float = 1.0):
    """Upload and replay a PCAP file"""
    if not os.path.exists(file_path):
        print(f"❌ Error: File not found: {file_path}")
        return False
    
    print(f"📤 Uploading PCAP file: {file_path}")
    print(f"⚡ Speed: {speed}x")
    
    try:
        with open(file_path, 'rb') as f:
            files = {'file': (os.path.basename(file_path), f, 'application/vnd.tcpdump.pcap')}
            data = {'speed': speed}
            response = requests.post('http://localhost:8000/pcap/upload', files=files, data=data)
            
            if response.status_code == 200:
                result = response.json()
                if result.get('success'):
                    print(f"✅ Success: {result.get('message')}")
                    print(f"📁 Filename: {result.get('filename')}")
                    return True
                else:
                    print(f"❌ Error: {result.get('error', 'Unknown error')}")
                    return False
            else:
                print(f"❌ HTTP Error {response.status_code}: {response.text}")
                return False
    except requests.exceptions.ConnectionError:
        print("❌ Error: Cannot connect to backend. Make sure the server is running on http://localhost:8000")
        return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def stop_replay():
    """Stop PCAP replay"""
    try:
        response = requests.post('http://localhost:8000/pcap/replay/stop')
        if response.status_code == 200:
            result = response.json()
            if result.get('success'):
                print("✅ PCAP replay stopped")
                return True
        print(f"❌ Error stopping replay: {response.text}")
        return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def check_stats():
    """Check current stats"""
    try:
        response = requests.get('http://localhost:8000/stats')
        if response.status_code == 200:
            stats = response.json()
            print("\n📊 Current Stats:")
            print(f"  Packets/sec: {stats.get('packets_per_sec', 0)}")
            print(f"  Bandwidth: {stats.get('bandwidth_bytes_per_sec', 0) / 1024:.2f} KB/s")
            print(f"  Active Sessions: {stats.get('active_sessions', 0)}")
            return True
        return False
    except Exception as e:
        print(f"❌ Error getting stats: {e}")
        return False

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python test_pcap_upload.py <pcap_file> [speed]")
        print("  python test_pcap_upload.py stop")
        print("  python test_pcap_upload.py stats")
        print("\nExamples:")
        print("  python test_pcap_upload.py test.pcap")
        print("  python test_pcap_upload.py test.pcap 2.0  # 2x speed")
        print("  python test_pcap_upload.py stop")
        sys.exit(1)
    
    command = sys.argv[1].lower()
    
    if command == 'stop':
        stop_replay()
    elif command == 'stats':
        check_stats()
    else:
        # Upload file
        file_path = sys.argv[1]
        speed = float(sys.argv[2]) if len(sys.argv) > 2 else 1.0
        upload_pcap(file_path, speed)
        print("\n💡 Tip: Check the dashboard at http://localhost:8000/static/ to see packets!")
        print("💡 Tip: Run 'python test_pcap_upload.py stats' to see current stats")
