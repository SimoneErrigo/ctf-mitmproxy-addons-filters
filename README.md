# ctf-mitmproxy-addons

A collection of addons and helper tools for [mitmproxy](https://mitmproxy.org/) tailored to Attack/Defense CTFs, especially when running mitmproxy in **reverse** or **transparent** proxy modes.

---

## 📦 What’s Included

### 🔄 mitm2pcap.py  
Capture live HTTP(S), raw TCP and gRPC-over-HTTP/2 traffic and write it to a `.pcap` file for offline analysis. Compatible with tools like Tulip, Packmate, Wireshark, etc.

### 🛡️ Example Filters  
A set of example addons under `filters/` demonstrating basic request/response blocking or modification. Handy for quick “on-the-fly” defenses during a CTF.

- **httpfilterexample.py** – block or alter HTTP paths, headers or payloads  
- **[…add your own custom filters here…]**

### 🏷️ Flag Tagging (mitmbodyfilter.py)  
Injects a custom `flag` header into any HTTP response whose body matches your flag regex. Then, in mitmweb’s UI you can simply filter on `flag:` to spot stolen flags in real time.

### ⚙️ genproxy.py  
A helper script that:

1. **Scans** the current directory tree for `docker-compose.yml` files  
2. **Parses** each compose file (via PyYAML)  
3. **Rebinds** service ports to `127.0.0.1` on available ports  
4. **Constructs** the appropriate `--mode reverse:` arguments for mitmweb  
5. **Backs up** originals under `backup-mitm/`  
6. **Emits** a `last_mitm_command.sh` script with the full `mitmweb …` invocation  

---

## 🚀 Prerequisites

```bash
pip install pyyaml
