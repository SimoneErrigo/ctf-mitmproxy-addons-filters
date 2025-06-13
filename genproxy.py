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
    print("✖  PyYAML non installed: `pip install pyyaml`", file=sys.stderr)
    sys.exit(1)

# ──────────────────────────────────────────────────────────────────────────────
# Globabl constants
# ──────────────────────────────────────────────────────────────────────────────
BASE_DIR: Path = Path.cwd()
BACKUP_DIR: Path = BASE_DIR / "backup-mitm"
LAST_CMD_FILE: Path = BASE_DIR / "last_mitm_command.sh"
PORT_RANGE: Tuple[int, int] = (12_000, 13_000)
ADDONS_DIR: Path = Path(".")

HTTP_TEMPLATE = '''\
from mitmproxy import http, ctx
import re
import urllib.parse

# Generated stub — customise me

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

# Generated stub — customise me

def tcp_message(flow: tcp.TCPFlow):
    message = flow.messages[-1]
    content = message.content
'''

BANNER = r"""
:'######:::'########:'##::: ##:'########::'########:::'#######::'##::::'##:'##:::'##:
'##... ##:: ##.....:: ###:: ##: ##.... ##: ##.... ##:'##.... ##:. ##::'##::. ##:'##::
 ##:::..::: ##::::::: ####: ##: ##:::: ##: ##:::: ##: ##:::: ##::. ##'##::::. ####:::
 ##::'####: ######::: ## ## ##: ########:: ########:: ##:::: ##:::. ###::::::. ##::::
 ##::: ##:: ##...:::: ##. ####: ##.....::: ##.. ##::: ##:::: ##::: ## ##:::::: ##::::
 ##::: ##:: ##::::::: ##:. ###: ##:::::::: ##::. ##:: ##:::: ##:: ##:. ##::::: ##::::
. ######::: ########: ##::. ##: ##:::::::: ##:::. ##:. #######:: ##:::. ##:::: ##::::
:......::::........::..::::..::..:::::::::..:::::..:::.......:::..:::::..:::::..:::::
"""

# ──────────────────────────────────────────────────────────────────────────────
# Utility functions
# ──────────────────────────────────────────────────────────────────────────────

def visible_directories() -> List[Path]:
    return sorted(
        p for p in BASE_DIR.iterdir()
        if p.is_dir() and not p.name.startswith(".") and p.name != BACKUP_DIR.name
    )

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

# ──────────────────────────────────────────────────────────────────────────────
# Patch functions for docker-compose
# ──────────────────────────────────────────────────────────────────────────────

def get_services_with_ports(compose_path: Path) -> List[str]:
    """Returns the list of services that have exposed ports"""
    try:
        data: Dict = yaml.safe_load(compose_path.read_text(encoding="utf8"))
    except Exception as e:
        print(f"✖  Error reading {compose_path}: {e}")
        return []

    if not data or "services" not in data:
        print(f"⚠️  No services in {compose_path.relative_to(BASE_DIR)}")
        return []

    services_with_ports = []
    for svc_name, svc_def in data["services"].items():
        if "ports" in svc_def and svc_def["ports"]:
            services_with_ports.append(svc_name)

    return services_with_ports

def patch_compose_service(compose_path: Path, service_name: str, used_ports: set[int]) -> Tuple[str, int, int]:
    """Change ports of a single service in docker-compose"""
    try:
        data: Dict = yaml.safe_load(compose_path.read_text(encoding="utf8"))
    except Exception as e:
        print(f"✖  Error reading {compose_path}: {e}")
        return "", 0, 0

    if not data or "services" not in data or service_name not in data["services"]:
        print(f"⚠️  Service {service_name} not found in {compose_path.relative_to(BASE_DIR)}")
        return "", 0, 0

    svc_def = data["services"][service_name]
    if "ports" not in svc_def or not svc_def["ports"]:
        print(f"⚠️  No ports exposed for service {service_name} in {compose_path.relative_to(BASE_DIR)}")
        return "", 0, 0

    # Get the first port mapping
    first_mapping = str(svc_def["ports"][0])
    parts = first_mapping.split(":")

    if len(parts) == 2:
        host_port, container_port = parts
    elif len(parts) == 3:
        _host_ip, host_port, container_port = parts
    else:
        print(f"⚠️  Unrecognised mapping '{first_mapping}' for service {service_name}")
        return "", 0, 0

    # Generate a new port
    new_port = random_free_port(used_ports)
    svc_def["ports"][0] = f"127.0.0.1:{new_port}:{container_port}"

    # Save the modified file
    compose_path.write_text(yaml.dump(data, sort_keys=False), encoding="utf8")
    return service_name, new_port, int(host_port)

# ──────────────────────────────────────────────────────────────────────────────
# Helper for saving/loading last command
# ──────────────────────────────────────────────────────────────────────────────

def save_last_command(cmd: str) -> None:
    LAST_CMD_FILE.write_text("#!/bin/sh\n" + cmd + "\n", encoding="utf8")
    LAST_CMD_FILE.chmod(LAST_CMD_FILE.stat().st_mode | 0o111)

def load_last_command() -> str | None:
    if not LAST_CMD_FILE.exists():
        return None
    lines = LAST_CMD_FILE.read_text(encoding="utf8").splitlines()
    return "\n".join(l for l in lines if not l.startswith("#!")).strip()

# ──────────────────────────────────────────────────────────────────────────────
# Workflow BUILD
# ──────────────────────────────────────────────────────────────────────────────

def do_build(args) -> None:
    global ADDONS_DIR

    if BACKUP_DIR.exists():
        print("❌  Environment already prepared: 'backup-mitm' exists. "
              "Run --restore or delete it manually.")
        return

    print(BANNER)

    # 1. Backup ----------------------------------------------------------------
    BACKUP_DIR.mkdir()
    if not args.skip_backups:
        print("Select folders to save in backup (y to include):")
        for folder in visible_directories():
            ans = input(f"  Backup '{folder.name}'? (y/N): ").strip().lower()
            if ans == "y":
                shutil.copytree(folder, BACKUP_DIR / folder.name, dirs_exist_ok=True)
                print(f"    ✔ Copied to backup/{folder.name}")

    # 2. Services selection -----------------------------------------------------
    services: List[Dict] = []
    print("\nNow indicate which folders are docker-compose services:")

    for folder in visible_directories():
        ans = input(f"  Is '{folder.name}' a service? (y/N): ").strip().lower()
        if ans != "y":
            continue

        compose_path = None
        for possible_name in ["docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"]:
            if (folder / possible_name).exists(): 
                compose_path = folder / possible_name
                break

        if compose_path is None:
            print(f"⚠️  No docker-compose file found; skipping.")
            continue

        # Find all services with exposed doors
        services_with_ports = get_services_with_ports(compose_path)

        if not services_with_ports:
            print(f"⚠️  No services with exposed ports found in {folder.name}")
            continue

        print(f"  Services with ports in {folder.name}: {', '.join(services_with_ports)}")

        # For each service with ports, ask for the protocol
        for service_name in services_with_ports:
            proto = ""
            while proto not in {"tcp", "http", "https"}:
                proto = input(f"    Protocol for {service_name} (tcp/http/https): ").strip().lower()

            cert_path: str | None = None
            if proto == "https":
                cert_path = input(f"    Path to fullchain.pem for {service_name} (Enter to omit): ").strip() or None

            services.append({
                "folder": folder,
                "service_name": service_name,
                "protocol": proto,
                "cert": cert_path
            })

    if not services:
        print("❌  No services chosen. Operation cancelled.")
        BACKUP_DIR.rmdir()
        return

    # 3. Global parameters ------------------------------------------------------
    if args.addons_dir is None:
        addons_dir_input = input("\nPath to mitmproxy addon folder: ").strip() or "."
    else:
        addons_dir_input = args.addons_dir
    ADDONS_DIR = Path(addons_dir_input).expanduser().resolve()
    ADDONS_DIR.mkdir(exist_ok=True, parents=True)

    if args.target_ip is None:
        target_ip = input("IP address on which to expose services: ").strip()
    else:
        target_ip = args.target_ip

    if args.web_port is None:
        web_port = input("Mitmproxy Web-UI port (e.g. 8085): ").strip() or "8081"
    else:
        web_port = args.web_port

    # 4. Patch compose + reverse-mode ------------------------------------------
    used_ports: set[int] = set()
    reverse_flags: List[str] = []
    ssl_insecure = False
    cert_flag: str | None = None

    for svc in services:

        svc_name, new_local_port, original_port = patch_compose_service(
            compose_path, svc["service_name"], used_ports
        )

        if new_local_port == 0:
            continue  # no ports / error

        scheme = svc["protocol"] if svc["protocol"] in {"http", "https"} else "tcp"
        reverse_flags.extend(
            ["--mode",
             f"reverse:{scheme}://127.0.0.1:{new_local_port}@{target_ip}:{original_port}"]
        )

        if svc["protocol"] == "https":
            ssl_insecure = True
            if svc["cert"] and cert_flag is None:
                cert_flag = svc["cert"]

    # 5. Addon + autogen -----------------------------------------------------
    addon_flags: list[str] = []
    existing = {f.name for f in ADDONS_DIR.glob("*.py")}

    for svc in services:
        stub_path = ensure_filter_file(ADDONS_DIR, svc["protocol"])
        if stub_path.name not in existing:
            if stub_path.is_relative_to(BASE_DIR):
                print(f"    ✔  Created {stub_path.relative_to(BASE_DIR)}")
            else:
                print(f"    ✔  Created {stub_path.absolute()}")
            existing.add(stub_path.name)  # avoid duplicates

    for f in ADDONS_DIR.glob("*.py"):
        addon_flags.extend(["-s", str(f)])

    # 6. Composition of mitmweb command----------------------------------------
    cmd_parts: List[str] = [
        "mitmweb",
        *reverse_flags,
        "--web-host", target_ip,
        "--web-port", str(web_port),
    ]
    if ssl_insecure:
        cmd_parts.append("--ssl-insecure")
    if cert_flag:
        cmd_parts.extend(["--certs", cert_flag])
    cmd_parts.extend(addon_flags)
    cmd_parts.extend(["--set", "keep_host_header"])

    final_cmd = " ".join(cmd_parts)

    # 7. Output -----------------------------------------------------------------
    print("\nGenerated mitmweb command:\n")
    print(textwrap.indent(final_cmd, "  "))

    save_last_command(final_cmd)
    print(f"\n✔  Command saved in {LAST_CMD_FILE.name}. Script completed.")

# ──────────────────────────────────────────────────────────────────────────────
# Workflow RESTORE
# ──────────────────────────────────────────────────────────────────────────────

def _infer_addons_dir_from_cmd(cmd: str) -> Path | None:
    parts = cmd.split()
    for i, token in enumerate(parts):
        if token == "-s" and i + 1 < len(parts):
            sample_path = Path(parts[i + 1])
            return (sample_path if sample_path.is_absolute()
                    else (BASE_DIR / sample_path)).resolve().parent
    return None

def do_restore() -> None:
    global ADDONS_DIR

    cmd = load_last_command()

    if cmd is None:
        for pattern in ("http_filter.py", "tcp_filter.py", "filter_*_filter.py"):
            for f in ADDONS_DIR.glob(pattern):
                try:
                    f.unlink()
                except Exception as exc:
                    print(f"  ⚠️  unable to delete {f}: {exc}")

    if not BACKUP_DIR.exists():
        print("❌  No backup to restore (folder 'backup-mitm' missing). Run --build first.")
        return

    if cmd:
        inferred_dir = _infer_addons_dir_from_cmd(cmd)
        if inferred_dir is not None:
            ADDONS_DIR = inferred_dir

    print("Restoring original files…")

    for item in BACKUP_DIR.iterdir():
        target = BASE_DIR / item.name
        if target.exists():
            if target.is_dir():
                shutil.rmtree(target)
            else:
                target.unlink()
        if item.is_dir():
            shutil.copytree(item, target)
        else:
            shutil.copy2(item, target)

    if cmd:
        for f in _extract_generated_filters(cmd):
            f = f.expanduser()
            if not f.is_absolute():
                f = (ADDONS_DIR / f).resolve()
            try:
                if f.exists():
                    f.unlink()
                    print(f"  • removed {f.relative_to(BASE_DIR) if f.is_relative_to(BASE_DIR) else f}")
            except Exception as exc:
                print(f"  ⚠️  unable to delete {f}: {exc}")

    try:
        if ADDONS_DIR.exists() and ADDONS_DIR != BASE_DIR and not any(ADDONS_DIR.iterdir()):
            ADDONS_DIR.rmdir()
    except Exception as exc:
        print(f"  ⚠️  unable to remove addons dir {ADDONS_DIR}: {exc}")

    shutil.rmtree(BACKUP_DIR, ignore_errors=True)
    LAST_CMD_FILE.unlink(missing_ok=True)

    print("✔  Restore completed and backup deleted.")

# ──────────────────────────────────────────────────────────────────────────────
# LAST workflow
# ──────────────────────────────────────────────────────────────────────────────

def show_last() -> None:
    cmd = load_last_command()
    if cmd:
        print("Last generated mitmweb command:\n")
        print(textwrap.indent(cmd, "  "))
    else:
        print("ℹ️  No previous command found. Run --build first.")

def _extract_generated_filters(cmd: str) -> list[Path]:
    filters: list[Path] = []
    parts = cmd.split()
    for i, token in enumerate(parts):
        if token == "-s" and i + 1 < len(parts):
            p = Path(parts[i + 1])
            if p.name.endswith("_filter.py"):
                filters.append(p)
    return filters

# ──────────────────────────────────────────────────────────────────────────────
# CLI parsing
# ──────────────────────────────────────────────────────────────────────────────

def parse_args(argv: List[str]):
    parser = argparse.ArgumentParser(
        prog="genproxy",
        description="Quickly generate a MITM environment with docker-compose.",
    )
    g = parser.add_mutually_exclusive_group(required=True)
    g.add_argument("-b", "--build",   action="store_true", help="build mitm environment")
    g.add_argument("-r", "--restore", action="store_true", help="restore from snapshot")
    g.add_argument("-l", "--last",    action="store_true", help="show last command")

    parser.add_argument("--skip-backups",   action="store_true", help="skip the backup prompt of the services")
    parser.add_argument("--addons-dir",     action="store", type=str, help="path to mitmproxy addons directory")
    parser.add_argument("--target-ip",      action="store", type=str, help="IP address on which to expose services")
    parser.add_argument("--web-port",       action="store", type=int, help="mitmweb http port")

    return parser.parse_args(argv)

# ──────────────────────────────────────────────────────────────────────────────
# main
# ──────────────────────────────────────────────────────────────────────────────

def main() -> None:
    args = parse_args(sys.argv[1:])

    if args.build:
        do_build(args)
    elif args.restore:
        do_restore()
    elif args.last:
        show_last()
    else:
        print("Use -h for help.")

if __name__ == "__main__":
    main()

