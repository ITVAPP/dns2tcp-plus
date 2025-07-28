# dns2tcp-plus

<div align="center">

[![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)](https://github.com/ITVAPP/dns2tcp-plus/releases)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-linux-lightgrey.svg)](https://github.com/ITVAPP/dns2tcp-plus)

English | [简体中文](README_CN.md)

A powerful DNS tool that converts DNS queries from UDP to TCP/TLS, featuring multi-server race queries, DNS over TLS support, and intelligent failover mechanisms.

</div>

---

## ✨ Key Features

- 🔒 **DNS over TLS (DoT)** - Automatic encryption for port 853, secure DNS queries
- 🏃 **Race Queries** - Query multiple servers simultaneously, use the fastest response
- 🔄 **Smart Failover** - Prioritize built-in DNS, automatically fallback to system DNS
- 🌍 **Hybrid DNS** - Seamlessly combine built-in servers with system DNS
- 🛡️ **DNS Response Validation** - Auto-filter poisoned responses, prevent DNS hijacking
- 🎯 **Smart Domain Routing** - Choose optimal servers based on domain suffix
- ⚡ **High Performance** - Memory pool optimization, SSL session caching
- 🔧 **Zero Configuration** - Auto-detect system DNS, works out of the box

## 🆕 v2.0.0 Major Update

### 1. DNS over TLS (DoT) Support
- Automatic encryption for port 853 queries
- SSL session caching for improved performance
- Support for major DoT providers (Google, Cloudflare)
- Zero configuration required

### 2. System DNS Integration
- Automatically loads DNS servers from `/etc/resolv.conf`
- Acts as fallback when built-in servers fail
- Can be disabled with `-f` flag for isolated environments

### 3. Intelligent Failover Mechanism
```
Built-in DNS (priority) → System DNS (fallback)
     ↓ All failed              ↓
     └──────────────→ Use cached system response
```

### 4. Performance Optimizations
- Memory pool for connection and context management
- SSL session reuse reduces handshake overhead
- Improved concurrent handling up to 256 queries

## 📦 Installation

### Pre-compiled Binaries (Recommended)

Download the static binary for your architecture from [Releases](https://github.com/ITVAPP/dns2tcp-plus/releases):

```bash
# Download (example for linux-amd64)
wget https://github.com/ITVAPP/dns2tcp-plus/releases/download/v2.0.0/dns2tcp-plus-linux-amd64
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

Dependencies:
- libev
- OpenSSL (for DoT support)

## 🚀 Quick Start

### Basic Usage

```bash
# Simplest usage - combines built-in + system DNS
dns2tcp-plus -L "127.0.0.1#5353"

# Test DNS resolution
dig @127.0.0.1 -p 5353 google.com

# Test DNS over TLS
dig @127.0.0.1 -p 5353 +tcp cloudflare.com
```

### DNS over TLS Examples

```bash
# Add custom DoT servers
dns2tcp-plus -L "127.0.0.1#5353" \
  -R "1.1.1.1#853" \
  -R "8.8.8.8#853" \
  -R "9.9.9.9#853"

# Mix TCP and DoT servers
dns2tcp-plus -L "127.0.0.1#5353" \
  -R "223.5.5.5#53" \      # TCP
  -R "1.1.1.1#853"         # DoT
```

### Domain Routing with DoT

```bash
# Use DoT for sensitive domains
dns2tcp-plus -L "127.0.0.1#5353" \
  -D "gmail.com:8.8.8.8#853" \
  -D "banking.com:1.1.1.1#853" \
  -D "cn:223.5.5.5#53"
```

### System DNS Control

```bash
# Disable system DNS (built-in only)
dns2tcp-plus -L "127.0.0.1#5353" -f

# Disable built-in servers (system only)
dns2tcp-plus -L "127.0.0.1#5353" -b

# Custom mix
dns2tcp-plus -L "127.0.0.1#5353" \
  -R "8.8.8.8#853" \      # Add DoT
  -b                       # Disable other built-ins, keep system
```

## 🌐 Built-in Servers

### TCP Servers (Port 53)
| Provider | Address | Description |
|----------|---------|-------------|
| Google | 8.8.8.8 | Global coverage, reliable |
| Cloudflare | 1.1.1.1 | Privacy-focused, fast |

### DoT Servers (Port 853)
| Provider | Address | Hostname | Description |
|----------|---------|----------|-------------|
| Google | 8.8.8.8 | dns.google | Encrypted Google DNS |
| Cloudflare | 1.1.1.1 | 1dot1dot1dot1.cloudflare-dns.com | Encrypted Cloudflare |

### System DNS
Automatically loaded from `/etc/resolv.conf` as fallback servers.

## 🛠️ Command Line Options

| Option | Description | Default | Limits |
|--------|-------------|---------|--------|
| `-L <ip[#port]>` | UDP listen address | Port defaults to 53 | - |
| `-R <ip[#port]>` | TCP/DoT remote server | Port 53=TCP, 853=DoT | Max 16 servers total |
| `-D <suffix:servers>` | Domain routing rule | None | Max 16 rules, 8 servers per rule |
| `-l <ip[#port]>` | TCP local address | System assigned | - |
| `-s <syncnt>` | TCP SYN retry count | System default | - |
| `-6` | Enable IPv6-only mode | Disabled | - |
| `-r` | Enable SO_REUSEPORT | Disabled | - |
| `-b` | Disable built-in servers | Built-in enabled | - |
| **`-f`** | Disable system DNS | System DNS enabled | - |
| `-v` | Verbose logging | Disabled | - |
| `-V` | Show version | - | - |
| `-h` | Show help | - | - |

## 💡 Advanced Usage

### 1. Maximum Security Configuration

```bash
# DoT only, no fallback to unencrypted
dns2tcp-plus -L "127.0.0.1#5353" \
  -R "1.1.1.1#853" \
  -R "8.8.8.8#853" \
  -R "9.9.9.9#853" \
  -b -f  # Disable all non-DoT servers
```

### 2. Performance Optimized Setup

```bash
# Mix of fast TCP and secure DoT
dns2tcp-plus -L "0.0.0.0#53" \
  -D "sensitive.com:1.1.1.1#853" \
  -D "local:192.168.1.1#53" \
  -r  # Enable SO_REUSEPORT for load balancing
```

### 3. Enterprise Configuration

```bash
dns2tcp-plus -L "0.0.0.0#53" \
  -D "internal.corp:10.0.0.1#53" \
  -D "*.internal:10.0.0.1#53" \
  -D "secure.corp:8.8.8.8#853" \
  -s 3 \  # Quick failover
  -v      # Verbose for monitoring
```

### 4. China Optimized Setup

```bash
dns2tcp-plus -L "127.0.0.1#5353" \
  -D "cn:223.5.5.5#53,119.29.29.29#53" \
  -D "com.cn:223.5.5.5#53" \
  -D "baidu.com:223.5.5.5#53" \
  -D "international:1.1.1.1#853"  # DoT for others
```

## 🏎️ How It Works

### Query Flow with Failover

```
Client Query
    ↓
dns2tcp-plus
    ├─→ Built-in DNS (Priority)
    │     ├─ 8.8.8.8:53 (TCP)
    │     ├─ 8.8.8.8:853 (DoT) ← Encrypted
    │     ├─ 1.1.1.1:53 (TCP)
    │     └─ 1.1.1.1:853 (DoT) ← Encrypted
    │
    └─→ System DNS (Fallback)
          ├─ 192.168.1.1:53
          └─ 8.8.4.4:53
```

### DoT Connection Flow

```
DNS Query → TCP Socket → SSL/TLS Handshake → Encrypted Query
                              ↓
                        Session Cached (Reused for next query)
```

### Response Priority

1. First valid response from built-in DNS wins
2. System DNS responses are cached but not used unless all built-ins fail
3. Bad IP filtering applies to all responses

## 📊 Performance Metrics

Based on v2.0.0 testing:

- **Concurrency**: 256 concurrent queries (limited by context pool)
- **Max Servers**: 16 total servers (built-in + custom + system)
- **Memory Usage**: < 3MB (with memory pools)
- **Connection Pool**: 2048 pre-allocated connections
- **Context Pool**: 256 pre-allocated contexts
- **DoT Overhead**: ~30ms first query, ~5ms with session reuse
- **Failover Time**: < 100ms to system DNS
- **SSL Session Cache**: 128 sessions, 5-minute timeout (300s)
- **DNS Packet Size**: Up to 1472 bytes
- **Bad IP Filtering**: Blocks 0.0.0.0, 127.0.0.1, 10.10.10.10, 240.0.0.0

## 🔒 Security Features

1. **DNS over TLS**: Prevents eavesdropping and tampering
2. **Response Validation**: Filters hijacked responses
3. **No Certificate Validation**: Simplified deployment (use with caution)
4. **Session Reuse**: Reduces attack surface from repeated handshakes

## ⚙️ Technical Features

- **TCP_NODELAY**: Optimized for low-latency DNS queries
- **Non-blocking I/O**: Event-driven architecture with libev
- **Memory Pools**: Zero-allocation design for hot paths
- **DNS Compression**: Proper handling of DNS label compression
- **Concurrent Design**: Each query spawns parallel connections
- **Smart Buffers**: 2-byte length prefix for TCP DNS format
- **IPv4/IPv6 Dual Stack**: Full support for both protocols

## 🔄 Changelog

### v2.0.0
- 🔒 Added DNS over TLS (DoT) support with SSL session caching
- 🔄 Added system DNS integration with intelligent failover
- ⚡ Added memory pool optimization for connections
- ✨ Improved built-in server configuration
- 📝 Enhanced logging for debugging DoT connections

### v1.3.0
- ✨ Added DNS response validation
- ✨ Added smart domain routing
- 🔧 Optimized DNS packet parsing

## 🐛 Troubleshooting

### DoT Connection Issues
```bash
# Enable verbose logging
dns2tcp-plus -L "127.0.0.1#5353" -v

# Check SSL handshake and session reuse
# Look for: "SSL session reused for..." messages
```

### System DNS Not Loading
```bash
# Check /etc/resolv.conf format
cat /etc/resolv.conf

# Force disable system DNS if needed
dns2tcp-plus -L "127.0.0.1#5353" -f
```

## 📄 License

This project is open-sourced under the MIT License.

---

<div align="center">

**If this project helps you, please give it a ⭐ Star!**

Made with ❤️ by ITVAPP

[⬆ Back to Top](#dns2tcp-plus)
</div>
