# ctf-mitmproxy-addons

A set of addons for [mitmproxy](https://mitmproxy.org/) designed for use in Attack/Defense CTFs, especially when deploying mitmproxy as a **reverse** or **transparent** proxy.

## 📦 What's Included

This repository includes several useful addons and examples:

### 🔄 mitm2pcap.py

This addon captures live network traffic intercepted by mitmproxy and writes it to a `.pcap` (Packet Capture) file. It supports:
- HTTP and HTTPS
- Raw TCP traffic
- gRPC over HTTP/2 (kind of)

The resulting `.pcap` file can be analyzed using tools such as [Tulip](https://github.com/OpenAttackDefenseTools/tulip.git), [Packmate](https://gitlab.com/packmate/Packmate.git), Wireshark, or any other packet analysis software.

### 🛡️ Example Filters

The `filters/` directory contains example addons that demonstrate how you can write basic filters to **block or modify malicious traffic** — useful for temporarily defending against common attacks during CTFs.

These are not meant to be complete protection mechanisms, but quick patches that can be adapted on-the-fly.

### 🏷️ Flag Tagging (flagbodyfilter.py)

Since mitmproxy does not currently support filtering on HTTP request/response **bodies** via the web interface, this addon injects a custom header (`flag`) into packets that contain a flag in the body. This allows filtering packets via the mitmweb UI by simply searching for the `flag` header — helping you **quickly identify stolen flags** in real time.

### 🧹 Auto-cleanup (autoclean.py)

During long CTF sessions, mitmweb can consume significant memory by keeping all flows in memory. This addon automatically manages memory usage by:
- **Periodic cleanup**: Runs cleanup checks at configurable intervals
- **Age-based removal**: Removes flows older than a specified age
- **Count-based limiting**: Keeps only the most recent N flows in memory

Default parameters (customizable in the addon):
```python
interval = 30      # seconds between cleanup checks
max_flows = 1000   # maximum number of flows to keep in memory
max_age = 600      # maximum age of flows in seconds (10 minutes)
```

This helps prevent memory exhaustion during intense CTF sessions while keeping the most relevant traffic visible.

### ⚙️ genproxy.py

A powerful helper tool to **automatically generate** a complete mitmproxy setup for all your local services. 

#### Features:
- **🔍 Auto-discovery**: Scans all visible directories for Docker-Compose services
- **📄 Multi-format support**: Detects `docker-compose.yml`, `docker-compose.yaml`, `compose.yml`, and `compose.yaml`
- **🔌 Smart port mapping**: Automatically patches service ports to bind to `127.0.0.1` on free ports (12000-13000 range)
- **🔒 HTTPS support**: Handles HTTPS services with certificate configuration
- **🎯 Protocol detection**: Supports HTTP, HTTPS, and raw TCP services
- **💾 Automatic backup**: Creates backups of original configurations before modification
- **🎨 Addon management**: Auto-generates filter stubs and loads all Python addons from specified directory
- **📝 Command persistence**: Saves the generated mitmweb command for easy re-execution

> **Prerequisites:**
> ```bash
> pip install pyyaml
> ```

## 🚀 Usage Examples

### Basic mitmproxy with addons

Here's how you might run mitmproxy with multiple addons in reverse proxy mode:

```bash
mitmweb --mode reverse:https://127.0.0.1:4999@192.168.1.117:5000 \
  -s mitm2pcap.py \
  -s filters/flagbodyfilter.py \
  -s filters/httpfilterexample.py \
  -s autoclean.py \
  --ssl-insecure
```

### Using genproxy.py

#### 🏗️ Build Mode - Interactive Setup

```bash
# Build and configure your MITM environment interactively:
python genproxy.py --build

# Example session:
# > Select folders to save in backup (y to include):
# >   Backup 'service1'? (y/N): y
# >   Backup 'service2'? (y/N): n
# > 
# > Now indicate which folders are docker-compose services:
# >   Is 'service1' a service? (y/N): y
# >   Services with ports in service1: web, api
# >     Protocol for web (tcp/http/https): https
# >     Path to fullchain.pem for HTTPS services in service1 (Enter to omit): /etc/certs/cert.pem
# >     Protocol for api (tcp/http/https): http
# > 
# > Path to mitmproxy addon folder: ./addons
# > IP address on which to expose services: 192.168.1.100
# > Mitmproxy Web-UI port (e.g. 8085): 8085
```

#### 🚀 Build Mode - With Arguments

Skip the interactive prompts by providing arguments:

```bash
# Quick setup with all parameters
python genproxy.py --build \
  --skip-backups \
  --addons-dir ./my-addons \
  --target-ip 192.168.1.100 \
  --web-port 8085
```

#### 🔄 Restore Mode

Restore your original Docker Compose configurations:

```bash
# Restore all original files and remove generated addons
python genproxy.py --restore

# Output:
# Restoring original files…
#   ✔ Restored service1
#   ✔ Restored service2
#   • removed ./addons/http_filter.py
#   • removed ./addons/tcp_filter.py
# ✔  Restore completed and backup deleted.
```

#### 📋 View Last Command

Check the last generated mitmweb command:

```bash
# Display the previously generated command
python genproxy.py --last

# Output:
# Last generated mitmweb command:
# 
#   mitmweb --mode reverse:https://127.0.0.1:12001@192.168.1.100:443 \
#           --mode reverse:http://127.0.0.1:12002@192.168.1.100:80 \
#           --web-host 192.168.1.100 --web-port 8085 \
#           --certs /etc/certs/cert.pem \
#           -s ./addons/http_filter.py \
#           -s ./addons/tcp_filter.py \
#           -s ./addons/custom_addon.py \
#           --set keep_host_header \
#           --ssl-insecure
```

### Generated Files

After running `genproxy.py --build`, you'll find:

```bash
.
├── backup-mitm/             # Backup of original directories
│   ├── service1/            # Original service1 with unmodified ports
│   └── service2/            # Original service2 with unmodified ports
├── last_mitm_command.sh     # Executable script with the full mitmweb command
├── service1/                # Modified docker-compose.yml (ports changed)
├── service2/                # Modified docker-compose.yml (ports changed)
└── addons/                  # Your addon directory
    ├── http_filter.py       # Auto-generated HTTP filter stub
    ├── tcp_filter.py        # Auto-generated TCP filter stub
    └── custom_addon.py      # Your existing addons (loaded automatically)
```

### Running the Generated Setup

```bash
# Make the script executable (already done by genproxy.py)
chmod +x last_mitm_command.sh

# Run your complete MITM setup
./last_mitm_command.sh
```

## 💡 CTF Pro Tips

### Memory Management During Long Sessions

When monitoring services for extended periods, use the `autoclean.py` addon to prevent memory exhaustion:

```bash
# Edit autoclean.py to adjust parameters for your needs:
# - Aggressive cleanup for limited memory: max_flows=500, max_age=300
# - Relaxed cleanup for analysis: max_flows=5000, max_age=1800

mitmweb --mode reverse:http://127.0.0.1:12000@10.10.10.10:80 \
  -s autoclean.py \
  -s mitm2pcap.py
```

### Quick Flag Detection Setup

Combine flagbodyfilter with autoclean for efficient flag monitoring:

```bash
# This setup tags flags and keeps memory usage low
mitmweb --mode reverse:http://127.0.0.1:12000@10.10.10.10:80 \
  -s filters/flagbodyfilter.py \
  -s autoclean.py \
  --web-host 0.0.0.0
  
# Now you can filter in the web UI by typing: ~h flag
```

## 📝 Notes

- The tool automatically loads **all `.py` files** in the addons directory as mitmproxy addons
- Port range 12000-13000 is used by default for local service bindings
- HTTPS certificates need to be specified only once per docker-compose file
- The `--ssl-insecure` flag is automatically added when HTTPS services are detected
- Original configurations are always backed up before modification (unless using `--skip-backups` for non-compose folders)
- The `autoclean.py` addon helps manage memory during long CTF sessions by periodically removing old flows