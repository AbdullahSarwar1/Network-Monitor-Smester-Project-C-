# Network Monitor

A real-time network packet capture and analysis tool for Windows, built as a Computer Networks (CN) project. It captures live traffic using **WinPcap/Npcap**, exposes a local HTTP API, and displays packet data through a browser-based dashboard.


## Features

- **Live Packet Capture** captures IPv4 and IPv6 traffic via libpcap/Npcap
- **Protocol Detection** identifies TCP, UDP, ICMP/ICMPv6, and other IP protocols
- **Service Mapping** maps well-known ports (HTTP, HTTPS, DNS, SSH, FTP, RDP, etc.) to service names
- **Real-time Statistics** total packets, total bytes, average packet size, packets/sec, per-protocol breakdown
- **Filtering** filter captured packets by protocol, source IP, or destination IP
- **Export / Import** export captured packets as CSV; import a previously saved CSV for offline review
- **Dark / Light Theme** toggle between themes directly in the UI
- **Rate Limiting** capped at 1000 packets/sec to prevent UI overload; stores up to 10,000 packets in memory


## Project Structure

```
network_monitor/
├── src/
│  └── main.cpp     # C++ backend packet capture, HTTP server, REST API
├── web/
│  ├── index.html    # Dashboard UI
│  ├── script.js     # Frontend logic (fetch, polling, filtering, CSV)
│  └── style.css     # Styling with dark/light theme support
└── network_monitor.exe  # Compiled Windows executable
```


## Architecture

```
[ Network Interface ]
    │ (libpcap / Npcap)
    ▼
[ C++ Backend main.cpp ]
 ├── Packet Handler   parses Ethernet / IPv4 / IPv6 / TCP / UDP / ICMP
 ├── In-Memory Store   circular buffer, max 10,000 packets
 ├── Stats Engine    protocol counts, byte totals
 └── HTTP Server :8080  serves REST API + static web files
    │
    ▼
[ Browser Dashboard ]
 ├── Capture Control   select interface, start/stop, export/import CSV
 ├── Filters Panel    filter by protocol / source IP / destination IP
 ├── Statistics Panel  live counters + protocol bar chart
 ├── Packet Table    scrollable per-packet detail view
 └── System Log     timestamped event log
```


## REST API

| Endpoint | Method | Description |
|---|---|---|
| `/` | GET | Serves the web dashboard |
| `/api/devices` | GET | Lists available network interfaces |
| `/api/start?device=<name>` | GET | Starts packet capture on the given interface |
| `/api/stop` | GET | Stops the active capture |
| `/api/packets?proto=&src=&dst=` | GET | Returns captured packets (with optional filters) |
| `/api/stats` | GET | Returns aggregate statistics |
| `/api/export` | GET | Downloads captured packets as `capture_log.csv` |
| `/api/status` | GET | Returns `{ capturing, packets }` status |


## Requirements

- **OS:** Windows (uses WinSock2 and Npcap/WinPcap)
- **Packet Capture Driver:** [Npcap](https://npcap.com/) (recommended) or WinPcap
- **Privileges:** Must be run as **Administrator** for raw packet capture
- **Browser:** Any modern browser (Chrome, Firefox, Edge)

### Build Dependencies (if compiling from source)

- C++17 compiler (e.g., MSVC or MinGW)
- [Npcap SDK](https://npcap.com/#download) (provides `wpcap.lib`, `Packet.lib`, `pcap.h`)
- WinSock2 (`ws2_32.lib`) included with Windows SDK


## Usage

### Running the Prebuilt Executable

1. Install [Npcap](https://npcap.com/) if not already installed.
2. Right-click `network_monitor.exe` **Run as Administrator**.
3. Open your browser and navigate to `http://localhost:8080`.
4. Select a network interface from the dropdown and click **Start Monitoring**.

### Building from Source

```bash
# Example with MinGW (adjust include/lib paths to your Npcap SDK location)
g++ -std=c++17 -o network_monitor.exe src/main.cpp \
  -I"C:/npcap-sdk/Include" \
  -L"C:/npcap-sdk/Lib/x64" \
  -lwpcap -lPacket -lws2_32
```


## Supported Protocols & Services

**Transport Protocols:** TCP, UDP, ICMP, ICMPv6

**Recognized Services (port mapping):**

| Port | Service | Port | Service |
|------|---------|------|---------|
| 22 | SSH | 80 | HTTP |
| 443 | HTTPS | 53 | DNS |
| 3306 | MySQL | 3389 | RDP |
| 5432 | PostgreSQL | 27017 | MongoDB |
| 21 | FTP | 25 | SMTP |
| 23 | Telnet | 5900 | VNC |
| … | *(30+ services total)* | | |


## Implementation Notes

- **Packet parsing** is done by casting raw byte buffers to packed `struct` types (`EtherHeader`, `IpHeader`, `TcpHeader`, etc.) with `#pragma pack(push, 1)` to avoid alignment padding.
- **Thread safety** is maintained via a `std::mutex` around the shared packet vector and counters.
- **Rate limiting** uses an `std::atomic<int>` counter reset every second to drop packets beyond the configured threshold.
- **Memory management** keeps the packet buffer bounded at 10,000 entries; older packets are evicted when the limit is reached.
- The HTTP server is a minimal hand-rolled implementation using WinSock2 each client connection is handled in a detached `std::thread`.


## Known Limitations

- Windows-only (relies on WinSock2 and Npcap).
- No PCAP file import/export (only CSV).
- The HTTP server is single-purpose and not suitable for production use.
- Captured packet payload content is not inspected (headers only).

## Author: Abdullah Sarwar (BCSF24A039) - 02/05/2026
