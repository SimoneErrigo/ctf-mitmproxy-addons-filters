import argparse
import shutil
import sys
import textwrap
from pathlib import Path
from random import randint
from typing import Dict, List, Tuple

try:
    import yaml
except ModuleNotFoundError:
    print("PyYAML not installed: `pip install pyyaml`", file=sys.stderr)
    sys.exit(1)

BASE_DIR: Path = Path.cwd()
BACKUP_DIR: Path = BASE_DIR / "backup-mitm"
LAST_CMD_FILE: Path = BASE_DIR / "last_mitm_command.sh"
PORT_RANGE: Tuple[int, int] = (12_000, 13_000)
ADDONS_DIR: Path = Path(".")

HTTP_TEMPLATE = '''\
import re
from mitmproxy import http, ctx
def request(flow: http.HTTPFlow):
    request = flow.request
    headers = request.headers
    path = request.path
    url = request.url
    body = request.text
'''

TCP_TEMPLATE = '''\
import re
from mitmproxy import tcp, ctx
def tcp_message(flow: tcp.TCPFlow):
    message = flow.messages[-1]
    content = message.content
'''

BANNER = r"""
:'######:::'########:'##::: ##:'########::'########:::'#######::'##::::'##:'##:::'##:
'##... ##:: ##.....:: ###:: ##: ##.... ##: ##.... ##:'##.... ##:. ##::'##::. ##:'##::
 ##:::..::: ##::::::: ####: ##: ##:::: ##: ##:::: ##: ##:::: ##::. ##'##::::. ####:::
 ##::'####: ######::: ## ## ##: ########:: ########:: ##:::: ##:::. ##:::::::. ##::::
 ##::: ##:: ##...:::: ##. ####: ##.... ##: ##.. ##::: ##:::: ##:::: ##:::::::: ##::::
 ##::: ##:: ##::::::: ##:. ###: ##:::: ##: ##::. ##:: ##:::: ##:::: ##:::::::: ##::::
. ######::: ########: ##::. ##: ########:: ##:::. ##:. #######::::: ##:::::::: ##::::
:......::::........::..::::..::........:::..:::::..:::.......::::::..:::::::::..:::::
"""

def visible_directories() -> List[Path]:
    return sorted(p for p in BASE_DIR.iterdir() if p.is_dir() and not p.name.startswith(".") and p.name != BACKUP_DIR.name)

def random_free_port(used: set[int]) -> int:
    while True:
        candidate = randint(*PORT_RANGE)
        if candidate not in used:
            used.add(candidate)
            return candidate

def ensure_filter_file(addons_dir: Path, protocol: str) -> Path:
    filename = "tcp_filter.py" if protocol == "tcp" else "http_filter.py"
    filepath = addons_dir / filename
    if filepath.exists():
        return filepath
    tpl = TCP_TEMPLATE if protocol == "tcp" else HTTP_TEMPLATE
    filepath.write_text(tpl, encoding="utf8")
    return filepath

def patch_compose(compose_path: Path, svc_protocols: Dict[str, str], used_ports: set[int]) -> List[Tuple[str, str, int, int]]:
    try:
        data: Dict = yaml.safe_load(compose_path.read_text(encoding="utf8"))
    except Exception as e:
        print(f"Error reading {compose_path}: {e}")
        return []
    if not data or "services" not in data:
        print(f"No services in {compose_path.relative_to(BASE_DIR)}")
        return []
    results: list[tuple[str, str, int, int]] = []
    for svc_name, svc_def in data.get("services", {}).items():
        if not svc_def.get("ports"):
            continue
        first_mapping = str(svc_def["ports"][0])
        parts = first_mapping.split(":")
        if len(parts) == 3:
            _ip, host_port, container_port = parts
        elif len(parts) == 2:
            host_port, container_port = parts
        else:
            print(f"Unrecognised mapping '{first_mapping}' in {svc_name}")
            continue
        new_port = random_free_port(used_ports)
        svc_def["ports"][0] = f"127.0.0.1:{new_port}:{container_port}"
        results.append((svc_name, svc_protocols.get(svc_name, "tcp"), new_port, int(host_port)))
    if results:
        compose_path.write_text(yaml.dump(data, sort_keys=False), encoding="utf8")
    return results

def save_last_command(cmd: str) -> None:
    LAST_CMD_FILE.write_text("#!/bin/bash\n" + cmd + "\n", encoding="utf8")
    LAST_CMD_FILE.chmod(LAST_CMD_FILE.stat().st_mode | 0o111)

def load_last_command() -> str | None:
    if not LAST_CMD_FILE.exists():
        return None
    lines = LAST_CMD_FILE.read_text(encoding="utf8").splitlines()
    return "\n".join(l for l in lines if not l.startswith("#!/bin/bash"))

def do_build() -> None:
    global ADDONS_DIR
    if BACKUP_DIR.exists():
        print("❌  Environment already prepared: 'backup-mitm' exists. Run --restore or delete it manually.")
        return
    print(BANNER)
    BACKUP_DIR.mkdir()
    print("Select folders to save in backup (y to include):")
    for folder in visible_directories():
        ans = input(f"  Backup '{folder.name}'? (y/N): ").strip().lower()
        if ans == "y":
            shutil.copytree(folder, BACKUP_DIR / folder.name)
            print(f"    ✔ Copied to backup/{folder.name}")

    services: List[Dict] = []
    print("\nSelect the folders that contain a docker-compose.yml:")
    for folder in visible_directories():
        ans = input(f"  Does '{folder.name}' contain a compose? (y/N): ").strip().lower()
        if ans != "y":
            continue
        compose_file = folder / "docker-compose.yml"
        try:
            compose_data = yaml.safe_load(compose_file.read_text(encoding="utf8"))
            service_names = list(compose_data.get("services", {}).keys())
        except Exception as exc:
            print(f"Cannot read {compose_file}: {exc}")
            continue
        proto_map: Dict[str, str] = {}
        cert_map: Dict[str, str | None] = {}
        for sname in service_names:
            proto = ""
            while proto not in {"tcp", "http", "https"}:
                proto = input(f"    Protocol for '{sname}' (tcp/http/https): ").strip().lower()
            proto_map[sname] = proto
            cert_map[sname] = None
            if proto == "https":
                cert_map[sname] = input(f"    Path to fullchain.pem for '{sname}' (Enter to omit): ").strip() or None
        services.append({"folder": folder, "protocols": proto_map, "certs": cert_map})
    if not services:
        print("No services chosen. Operation cancelled.")
        BACKUP_DIR.rmdir()
        return
    addons_dir_input = input("\nPath to mitmproxy addon folder: ").strip() or "."
    ADDONS_DIR = Path(addons_dir_input).expanduser().resolve()
    ADDONS_DIR.mkdir(exist_ok=True, parents=True)
    target_ip = input("IP address on which to expose services: ").strip()
    web_port = input("Mitmproxy Web-UI port (e.g. 8085): ").strip() or "8081"
    used_ports: set[int] = set()
    reverse_flags: List[str] = []
    ssl_insecure = False
    cert_flag: str | None = None
    protocol_set: set[str] = set()

    for entry in services:
        compose_path = entry["folder"] / "docker-compose.yml"
        if not compose_path.exists():
            print(f"Warning: {compose_path.relative_to(BASE_DIR)} not found, skipped.")
            continue
        results = patch_compose(compose_path, entry["protocols"], used_ports)
        if not results:
            continue
        for svc_name, proto, new_local_port, original_port in results:
            scheme = proto if proto in {"http", "https"} else "tcp"
            reverse_flags.extend([
                "--mode",
                f"reverse:{scheme}://127.0.0.1:{new_local_port}@{target_ip}:{original_port}"
            ])
            protocol_set.add(proto)
            if proto == "https":
                ssl_insecure = True
                cert_file = entry["certs"].get(svc_name)
                if cert_file and cert_flag is None:
                    cert_flag = cert_file
    addon_flags: list[str] = []
    existing = {f.name for f in ADDONS_DIR.glob("*.py")}
    for proto in protocol_set:
        stub_path = ensure_filter_file(ADDONS_DIR, proto)
        if stub_path.name not in existing:
            print(f"    Created {stub_path.relative_to(BASE_DIR)}")
            existing.add(stub_path.name)
    for f in ADDONS_DIR.glob("*.py"):
        addon_flags.extend(["-s", str(f)])
    cmd_parts: List[str] = [
        "mitmweb",
        *reverse_flags,
        "--web-host", target_ip,
        "--web-port", web_port,
    ]
    if ssl_insecure:
        cmd_parts.append("--ssl-insecure")
    if cert_flag:
        cmd_parts.extend(["--certs", cert_flag])
    cmd_parts.extend(addon_flags)
    cmd_parts.extend(["--set", "keep_host_header"])
    final_cmd = " ".join(cmd_parts)
    print("\nGenerated mitmweb command:\n")
    print(textwrap.indent(final_cmd, "  "))
    save_last_command(final_cmd)
    print(f"\n✔  Command saved in {LAST_CMD_FILE.name}. Script completed.")

def _infer_addons_dir_from_cmd(cmd: str) -> Path | None:
    parts = cmd.split()
    for i, token in enumerate(parts):
        if token == "-s" and i + 1 < len(parts):
            sample_path = Path(parts[i + 1])
            return (sample_path if sample_path.is_absolute() else (BASE_DIR / sample_path)).resolve().parent
    return None

def restore() -> None:
    if not BACKUP_DIR.exists():
        print("No backup directory found.")
        return
    for item in BACKUP_DIR.iterdir():
        target = BASE_DIR / item.name
        if target.exists():
            print(f"Skipping existing {target}")
            continue
        if item.is_dir():
            shutil.copytree(item, target)
        else:
            shutil.copy2(item, target)
    shutil.rmtree(BACKUP_DIR)
    print("Backup restored and directory removed.")

def main() -> None:
    parser = argparse.ArgumentParser(prog="genproxy")
    parser.add_argument("--build", action="store_true", help="Prepare environment and build mitmweb command")
    parser.add_argument("--restore", action="store_true", help="Undo --build (move backup-mitm back)")
    parser.add_argument("--last", action="store_true", help="Show last generated command")
    args = parser.parse_args()
    if args.build:
        do_build()
    elif args.restore:
        restore()
    elif args.last:
        last = load_last_command()
        if last:
            print(last)
        else:
            print("No previous command stored.")
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
