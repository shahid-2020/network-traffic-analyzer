# Network Traffic Analyzer

This project is a C-based network traffic analysis tool built using the `libpcap` library. It captures live network packets on a specified interface, extracts key metadata, and logs the results to a CSV file for further analysis.

## Overview

The tool provides a basic packet sniffing capability with structured logging. It captures Ethernet packets, inspects IP, TCP, UDP, and ICMP headers, and records attributes such as MAC addresses, IP addresses, ports, flags, TTL, sequence numbers, and acknowledgment numbers.

## Features

- Captures live traffic on a specified network interface
- Supports Ethernet, IPv4, TCP, UDP, and ICMP protocols
- Logs the following details:
  - Timestamp
  - Source and destination MAC addresses
  - Source and destination IP addresses
  - Source and destination ports (if applicable)
  - Protocol type (TCP, UDP, ICMP, etc.)
  - Packet direction (placeholder logic for now)
  - TCP flags (e.g., SYN, ACK, FIN, RST)
  - Packet size (original and captured length)
  - TTL (Time To Live)
  - TCP sequence and acknowledgment numbers
- Writes logs to a CSV file: `./exec/packets.csv`

## Project Structure

```

.
├── Makefile
├── README.md
├── exec/                   # Output directory
│   └── packets.csv         # Packet log file (generated at runtime)
├── src/
│   └── traffic\_analyzer.c  # Main source code

````

## Prerequisites

Install `libpcap`, the packet capture library used in this project.

### On Linux:
```bash
sudo apt-get update
sudo apt-get install libpcap-dev
````

### On macOS:

`libpcap` is included by default. You can compile directly using `gcc`.

> Note: Root privileges (via `sudo`) are typically required for live packet capture.

## Finding Your Network Interface

To determine the appropriate network interface:

### macOS:

```bash
ifconfig
```

Common interfaces:

* `en0` – Ethernet or Wi-Fi
* `en1` – Sometimes Wi-Fi
* `lo0` – Loopback (localhost)

### Linux:

```bash
ip link
```

Look for active interfaces like `eth0`, `wlan0`, etc.

## Build Instructions

To build the program using the provided `Makefile`:

```bash
make build
```

This will:

* Compile the source file
* Place the executable in `./exec/traffic_analyzer`

## Run Instructions

To run the traffic analyzer:

```bash
sudo ./exec/traffic_analyzer <interface>
```

Example:

```bash
sudo ./exec/traffic_analyzer en0
```

To build and run together using the default interface `en0`:

```bash
make run
```

## Output

Captured packet data is written to a CSV file:

```
./exec/packets.csv
```

### CSV Columns:

* Timestamp
* Source MAC address
* Destination MAC address
* Source IP address
* Source port
* Destination IP address
* Destination port
* Protocol (TCP/UDP/ICMP)
* Direction (currently returns "Unknown")
* TCP Flags (if applicable)
* Original packet length
* Captured packet length
* TTL (Time To Live)
* TCP sequence number
* TCP acknowledgment number

Sample CSV row:

```
2019-12-15 14:10:05,1a:2b:3c:4d:5e:6f,6f:5e:4d:3c:2b:1a,192.168.1.10,443,192.168.1.2,53622,TCP,Unknown,SYN|ACK,60,60,64,123456789,987654321
```

## Clean Build Artifacts

To clean up the compiled binary and logs:

```bash
make clean
```

## Notes

* Capturing packets on a network may require administrative privileges and authorization.
* Packet direction detection is currently a placeholder and not implemented using routing logic.

## Potential Extensions

* Use routing tables or local IP detection for accurate packet direction
* Add DNS, HTTP protocol parsing
* Visualize packet logs
* Export logs in JSON format
* Implement packet filtering options