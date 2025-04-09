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

## 🚀 Usage Example

Here's how you might run mitmproxy with multiple addons in reverse proxy mode:

```bash
mitmweb --mode reverse:https://127.0.0.1:4999@192.168.1.117:5000 \
        -s mitm2pcap.py \
        -s filters/mitmbodyfilter.py \
        -s filters/httpfilterexample.py