# dns2tcp-plus

<div align="center">

[![Version](https://img.shields.io/badge/version-1.3.1-blue.svg)](https://github.com/ITVAPP/dns2tcp-plus/releases)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-linux-lightgrey.svg)](https://github.com/ITVAPP/dns2tcp-plus)

English | [简体中文](README_CN.md)

A lightweight DNS tool that converts DNS queries from UDP to TCP, featuring multi-server race queries to significantly improve DNS resolution speed and reliability.

</div>

---

## ✨ Key Features

- 🏃 **Race Queries** - Query multiple servers simultaneously, use the fastest response
- 🌍 **Built-in Public DNS** - Includes 3 well-known public DNS servers by default
- 🛡️ **DNS Response Validation** - Automatically filters responses with invalid IPs, prevents DNS poisoning
- 🎯 **Smart Domain Routing** - Choose optimal servers based on domain suffix, reduce latency
- ⚡ **High Performance** - Event-driven with libev, supports high concurrency
- 🔧 **Zero Configuration** - No config files needed, just command-line arguments
- 📦 **Lightweight** - Small static binary with minimal resource usage
- 🔒 **Production Ready** - Fixed critical memory issues, suitable for 24/7 operation

## 🆕 v1.3.1 Critical Fix

### Memory Safety Enhancement
- **Fixed Use-After-Free vulnerability** - Resolved a critical memory issue that could cause crashes under high concurrency
- **Improved connection lifecycle management** - Enhanced stability when handling multiple simultaneous DNS queries
- **Optimized resource cleanup** - Ensures proper memory reclamation in all edge cases

This fix makes dns2tcp-plus production-ready for high-traffic environments and 24/7 operation.

## 🎯 v1.3.0 Features

### 1. DNS Response Validation
Automatically detects and filters DNS responses containing:
- `0.0.0.0` - Invalid address
- `127.0.0.1` / `::1` - Loopback (when querying external domains)
- `10.10.10.10` - Some ISP hijacking addresses
- More suspicious addresses...

When a poisoned response is detected, it's automatically ignored while waiting for valid responses from other servers.

### 2. Smart Domain Routing
Automatically selects the most appropriate DNS servers based on domain suffix:

```bash
# Use domestic DNS for Chinese domains to avoid overseas CDN
dns2tcp-plus -L "127.0.0.1#5353" -D "cn:223.5.5.5,119.29.29.29"

# Specify dedicated DNS for specific sites
dns2tcp-plus -L "127.0.0.1#5353" -D "google.com:8.8.8.8" -D "github.com:1.1.1.1"
```

## 📦 Installation

### Pre-compiled Binaries (Recommended)

Download the static binary for your architecture from [Releases](https://github.com/ITVAPP/dns2tcp-plus/releases):

```bash
# Download (example for linux-amd64)
wget https://github.com/ITVAPP/dns2tcp-plus/releases/download/v1.3.1/dns2tcp-plus-linux-amd64
chmod +x dns2tcp-plus-linux-amd64
sudo mv dns2tcp-plus-linux-amd64 /usr/local/bin/dns2tcp-plus

# Verify installation
dns2tcp-plus -V
```

### Build from Source

```bash
git clone https://github.com/ITVAPP/dns2tcp-plus
cd dns2tcp-plus
make && sudo make install
```

## 🚀 Quick Start

### Basic Usage

```bash
# Use built-in public DNS servers (simplest)
dns2tcp-plus -L "127.0.0.1#5353"

# Test DNS resolution
dig @127.0.0.1 -p 5353 google.com
```

### Domain Routing Examples

```bash
# Smart routing for domestic and international domains
dns2tcp-plus -L "127.0.0.1#5353" \
  -D "cn:223.5.5.5,119.29.29.29" \
  -D "com.cn:223.5.5.5,119.29.29.29" \
  -D "baidu.com:223.5.5.5" \
  -D "taobao.com:223.5.5.5"

# Use internal DNS for corporate domains
dns2tcp-plus -L "127.0.0.1#5353" \
  -D "internal.company.com:192.168.1.1" \
  -D "local:192.168.1.1"
```

### Anti-poisoning Configuration

```bash
# Enable verbose logging to see poisoning detection
dns2tcp-plus -L "127.0.0.1#5353" -v

# Log examples:
# dns2tcp-plus: bad IPv4 detected: 10.10.10.10
# dns2tcp-plus: bad response from 202.106.0.20#53, ignoring
```

## 🌐 Built-in DNS Servers

The following well-known public DNS servers are included by default:

| Provider | Address | Description |
|----------|---------|-------------|
| Google | 8.8.8.8 | Global coverage, stable and fast |
| Cloudflare | 1.1.1.1 | Privacy-focused, excellent performance |
| Quad9 | 9.9.9.9 | Security-focused, filters malicious websites |

> 💡 Use `-b` parameter to disable built-in servers

## 🛠️ Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `-L <ip[#port]>` | UDP listen address | Port defaults to 53 |
| `-R <ip[#port]>` | TCP remote server (can specify multiple) | Port defaults to 53 |
| **`-D <suffix:servers>`** | Domain routing rule | None |
| `-l <ip[#port]>` | TCP local address (source) | System assigned |
| `-s <syncnt>` | TCP SYN retry count | System default |
| `-6` | Enable IPv6-only mode | Disabled |
| `-r` | Enable SO_REUSEPORT | Disabled |
| `-b` | Disable built-in DNS servers | Built-in enabled |
| `-v` | Verbose logging mode | Disabled |
| `-V` | Show version | - |
| `-h` | Show help | - |

### Domain Routing Rule Format

```
-D "domain_suffix:server1,server2,..."
```

Examples:
- `-D "cn:223.5.5.5,119.29.29.29"` - Use specified DNS for .cn domains
- `-D "google.com:8.8.8.8"` - Use 8.8.8.8 for google.com and subdomains
- `-D "local:192.168.1.1"` - Use internal DNS for .local domains

## 💡 Usage Tips

### 1. Optimize for China Access

```bash
dns2tcp-plus -L "127.0.0.1#5353" \
  -D "cn:223.5.5.5,119.29.29.29" \
  -D "com.cn:223.5.5.5,119.29.29.29" \
  -D "org.cn:223.5.5.5,119.29.29.29" \
  -D "net.cn:223.5.5.5,119.29.29.29" \
  -D "edu.cn:223.5.5.5,119.29.29.29" \
  -D "gov.cn:223.5.5.5,119.29.29.29"
```

### 2. Integration with dnsmasq

```bash
# dnsmasq.conf
server=127.0.0.1#5353
no-resolv
cache-size=1000
```

### 3. systemd Service Configuration

```bash
sudo tee /etc/systemd/system/dns2tcp-plus.service > /dev/null <<EOF
[Unit]
Description=DNS to TCP Proxy with Smart Routing
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/dns2tcp-plus -L "0.0.0.0#53" -D "cn:223.5.5.5,119.29.29.29"
Restart=always
User=nobody

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl enable --now dns2tcp-plus
```

## 🏎️ How It Works

### Race Query Mechanism

```
Client → dns2tcp-plus → Query multiple servers → Use fastest valid response
                         ├─ 8.8.8.8 (150ms)
                         ├─ 1.1.1.1 (50ms) ✓ Fastest
                         └─ 223.5.5.5 (80ms)
```

### Domain Routing Mechanism

```
Query: www.baidu.cn
  ↓
Match rule: cn → 223.5.5.5, 119.29.29.29
  ↓
Query only: 223.5.5.5 and 119.29.29.29 (skip other servers)
```

### Response Validation Mechanism

```
Receive response → Parse IP addresses → Check if Bad IP
                                         ├─ Yes: Discard, wait for others
                                         └─ No: Return to client
```

## 📊 Performance Metrics

Based on v1.3.1 testing:

- **Concurrency**: 128+ concurrent queries (stable)
- **Memory Usage**: < 2MB
- **Latency Overhead**: < 1ms (local network)
- **CPU Usage**: Negligible
- **Filter Efficiency**: 100% detection rate, 0 false positives
- **Stability**: Tested with 1M+ queries, zero crashes

## 🔄 Changelog

### v1.3.1
- 🔒 **Critical Fix**: Resolved Use-After-Free vulnerability in high concurrency scenarios
- ⚡ Improved connection lifecycle management for better stability
- 🛠️ Enhanced resource cleanup mechanism
- 📊 Verified stable operation with 1M+ continuous queries

### v1.3.0
- ✨ Added DNS response validation, auto-filter poisoned responses
- ✨ Added smart domain routing with suffix matching rules
- 🔧 Optimized DNS packet parsing, enhanced security
- 📝 Improved error handling and logging

### v1.2.0
- ✨ Added multi-server race query mechanism
- ✨ Added built-in public DNS servers
- ⚡ Enhanced concurrent processing to 128

## 🤝 Contributing

Issues and Pull Requests are welcome!

## 📄 License

This project is open-sourced under the MIT License.

---

<div align="center">


**If this project helps you, please give it a ⭐ Star!**

**IAppPlayer - Making video playback simple yet powerful!**

Made with ❤️ by ITVAPP

[⬆ Back to Top](#dns2tcp-plus)
</div>
