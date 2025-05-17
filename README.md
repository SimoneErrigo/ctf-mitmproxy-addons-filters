# ctf-mitmproxy-addons

A set of addons for [mitmproxy](https://mitmproxy.org/) designed for use in Attack/Defense CTFs, especially when deploying mitmproxy as a **reverse** or **transparent** proxy.

## 📦 What's Included

This repository includes several useful addons and examples:

### 🔄 mitm2pcap.py
This addon captures live network traffic intercepted by mitmproxy and writes it to a `.pcap` (Packet Capture) file. It supports:

- HTTP and HTTPS  
- Raw TCP traffic  
- gRPC over HTTP/2  

The resulting `.pcap` file can be analyzed using tools such as [Tulip](https://github.com/OpenAttackDefenseTools/tulip.git), [Packmate](https://gitlab.com/packmate/Packmate.git), Wireshark, or any other packet analysis software.

### 🛡️ Example Filters
The `filters/` directory contains example addons that demonstrate how you can write basic filters to **block or modify malicious traffic** — useful for temporarily defending against common attacks during CTFs.

These are not meant to be complete protection mechanisms, but quick patches that can be adapted on-the-fly.

### 🏷️ Flag Tagging (mitmbodyfilter.py)
Since mitmproxy does not currently support filtering on HTTP request/response **bodies** via the web interface, this addon injects a custom header (`flag`) into packets that contain a flag in the body. This allows filtering packets via the mitmweb UI by simply searching for the `flag` header — helping you **quickly identify stolen flags** in real time.

### ⚙️ genproxy.py
A helper tool to **automatically generate** a shell script that launches `mitmweb` pre-configured for all your local services. It will:

- **Scan** all visible directories for Docker-Compose services  
- **Parse** each `docker-compose.yml` with PyYAML  
- **Patch** service port mappings to bind to `127.0.0.1` on a free port  
- **Build** the appropriate `--mode reverse:` flags for mitmweb  
- **Generate** a `last_mitm_command.sh` script you can re-run any time  
- **Backup** your original service directories under `backup-mitm/` before modifying  

> **Prerequisite:**  
> ```bash
> pip install pyyaml
> ```

## 🚀 Usage Examples

Here’s how you might run mitmproxy with multiple addons in reverse proxy mode:

```bash
mitmweb --mode reverse:https://127.0.0.1:4999@192.168.1.117:5000 \
        -s mitm2pcap.py \
        -s filters/mitmbodyfilter.py \
        -s filters/httpfilterexample.py \
        --ssl-insecure
```

Alternatively, you can use genproxy.py to automate the above for all services in your current directory:

# Build and configure your MITM environment in one go:
python genproxy.py --build

# If you ever need to restore original compose files:
python genproxy.py --restore

# To just view the last generated mitmweb command:
python genproxy.py --last

Once --build completes, you’ll find:

    A backup-mitm/ directory with originals

    A last_mitm_command.sh script with the full mitmweb command

Run that script directly anytime to bring your environment back up.
