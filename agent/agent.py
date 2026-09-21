"""
Агент, що встановлюється на кожен клієнтський Windows ПК.

Що робить:
  1. Раз на кілька секунд повідомляє серверу "я живий" (heartbeat).
  2. Отримує з сервера актуальний список заблокованих програм.
  3. У фоні постійно перевіряє запущені процеси і завершує ("вбиває")
     ті, що є в списку заблокованих — тобто якщо користувач спробує
     запустити заблоковану програму, вона миттєво закриється.

Список заблокованих програм кешується локально (blocked_cache.json),
тож якщо зв'язок з сервером тимчасово пропаде — блокування продовжує
працювати за останніми відомими правилами.

Встановлення (коротко, детальніше — у README.md):
  pip install -r requirements.txt
  set PC_CONTROL_SERVER=http://<IP-адмінського-ПК>:8765
  set PC_CONTROL_API_KEY=<такий самий ключ, як на сервері>
  pythonw agent.py
"""

import ctypes
import json
import os
import socket
import subprocess
import sys
import time
import uuid

import psutil
import requests

APP_DIR = os.path.dirname(os.path.abspath(__file__))
AGENT_ID_FILE = os.path.join(APP_DIR, "agent_id.txt")
CACHE_FILE = os.path.join(APP_DIR, "blocked_cache.json")
DOMAIN_CACHE_FILE = os.path.join(APP_DIR, "blocked_domains_cache.json")

HOSTS_PATH = r"C:\Windows\System32\drivers\etc\hosts"
HOSTS_MARK_BEGIN = "# === PCControlAgent BLOCK START (не редагуйте вручну) ==="
HOSTS_MARK_END = "# === PCControlAgent BLOCK END ==="

SERVER_URL = os.environ.get("PC_CONTROL_SERVER", "http://127.0.0.1:8765").rstrip("/")
API_KEY = os.environ.get("PC_CONTROL_API_KEY", "change-me-please")

HEARTBEAT_INTERVAL_SEC = 5   # як часто звітувати серверу і оновлювати правила
KILL_CHECK_INTERVAL_SEC = 1  # як часто перевіряти й вбивати процеси
HTTP_TIMEOUT_SEC = 5

# Процеси, які ніколи не будемо трогати, навіть якщо їх випадково додадуть
# у список (захист від блокування критичних системних процесів).
NEVER_KILL = {"system", "system idle process", "svchost", "wininit", "csrss", "smss", "lsass", "explorer"}


def get_agent_id() -> str:
    if os.path.exists(AGENT_ID_FILE):
        with open(AGENT_ID_FILE, "r", encoding="utf-8") as f:
            return f.read().strip()
    new_id = str(uuid.uuid4())
    with open(AGENT_ID_FILE, "w", encoding="utf-8") as f:
        f.write(new_id)
    return new_id


def norm(name: str) -> str:
    name = name.strip().lower()
    if name.endswith(".exe"):
        name = name[:-4]
    return name


def load_cached_blocklist() -> set:
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, "r", encoding="utf-8") as f:
                return set(json.load(f))
        except Exception:
            return set()
    return set()


def save_cached_blocklist(blocked: set):
    try:
        with open(CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(sorted(blocked), f)
    except Exception:
        pass


def fetch_rules(agent_id: str) -> set:
    resp = requests.get(
        f"{SERVER_URL}/api/rules/{agent_id}",
        headers={"X-API-Key": API_KEY},
        timeout=HTTP_TIMEOUT_SEC,
    )
    resp.raise_for_status()
    data = resp.json()
    return {norm(x) for x in data.get("blocked", [])}


def norm_domain(domain: str) -> str:
    d = domain.strip().lower()
    d = d.replace("https://", "").replace("http://", "")
    d = d.split("/", 1)[0]
    d = d.split(":", 1)[0]
    if d.startswith("www."):
        d = d[4:]
    return d.rstrip(".")


def fetch_site_rules(agent_id: str) -> set:
    resp = requests.get(
        f"{SERVER_URL}/api/site-rules/{agent_id}",
        headers={"X-API-Key": API_KEY},
        timeout=HTTP_TIMEOUT_SEC,
    )
    resp.raise_for_status()
    data = resp.json()
    return {norm_domain(x) for x in data.get("blocked_domains", [])}


def load_cached_domains() -> set:
    if os.path.exists(DOMAIN_CACHE_FILE):
        try:
            with open(DOMAIN_CACHE_FILE, "r", encoding="utf-8") as f:
                return set(json.load(f))
        except Exception:
            return set()
    return set()


def save_cached_domains(domains: set):
    try:
        with open(DOMAIN_CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(sorted(domains), f)
    except Exception:
        pass


def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def apply_hosts_block(domains: set):
    """Переписує керовану ділянку файлу hosts заблокованими доменами.
    Не чіпає нічого, що користувач/інші програми дописали поза маркерами."""
    if not os.path.exists(HOSTS_PATH):
        return
    try:
        with open(HOSTS_PATH, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except PermissionError:
        print("[WARN] Немає прав на читання hosts — потрібен запуск від SYSTEM/адміністратора.")
        return

    # Прибираємо стару керовану ділянку, якщо вона є
    if HOSTS_MARK_BEGIN in content:
        before, rest = content.split(HOSTS_MARK_BEGIN, 1)
        _, after = rest.split(HOSTS_MARK_END, 1) if HOSTS_MARK_END in rest else (rest, "")
        base = before.rstrip() + "\n"
    else:
        base = content.rstrip() + "\n"

    if domains:
        lines = [HOSTS_MARK_BEGIN]
        for d in sorted(domains):
            lines.append(f"0.0.0.0 {d}")
            lines.append(f"0.0.0.0 www.{d}")
        lines.append(HOSTS_MARK_END)
        new_content = base + "\n" + "\n".join(lines) + "\n"
    else:
        new_content = base

    if new_content == content:
        return  # нічого не змінилось, не пишемо файл дарма

    try:
        with open(HOSTS_PATH, "w", encoding="utf-8") as f:
            f.write(new_content)
        subprocess.run(["ipconfig", "/flushdns"], capture_output=True)
        print(f"[SITES] Оновлено hosts: заблоковано {len(domains)} домен(ів).")
    except PermissionError:
        print("[WARN] Немає прав на запис hosts — потрібен запуск від SYSTEM/адміністратора.")


def send_heartbeat(agent_id: str):
    requests.post(
        f"{SERVER_URL}/api/heartbeat",
        headers={"X-API-Key": API_KEY},
        json={"agent_id": agent_id, "hostname": socket.gethostname()},
        timeout=HTTP_TIMEOUT_SEC,
    )


def kill_blocked_processes(blocked: set):
    if not blocked:
        return
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            name = proc.info["name"] or ""
            key = norm(name)
            if key in NEVER_KILL:
                continue
            if key in blocked:
                proc.kill()
                print(f"[BLOCKED] Завершено процес: {name} (pid={proc.info['pid']})")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue


def main():
    agent_id = get_agent_id()
    blocked = load_cached_blocklist()
    blocked_domains = load_cached_domains()
    apply_hosts_block(blocked_domains)  # застосувати кеш одразу при старті

    if not is_admin():
        print("[WARN] Агент запущено без прав адміністратора/SYSTEM — блокування сайтів (hosts) не працюватиме.")

    print(f"Агент запущено. agent_id={agent_id}, hostname={socket.gethostname()}")
    print(f"Сервер: {SERVER_URL}")

    last_sync = 0.0
    while True:
        now = time.time()
        if now - last_sync >= HEARTBEAT_INTERVAL_SEC:
            try:
                send_heartbeat(agent_id)
                blocked = fetch_rules(agent_id)
                save_cached_blocklist(blocked)

                new_domains = fetch_site_rules(agent_id)
                if new_domains != blocked_domains:
                    save_cached_domains(new_domains)
                blocked_domains = new_domains
                apply_hosts_block(blocked_domains)  # завжди перевіряємо й за потреби відновлюємо файл
            except Exception as e:
                print(f"[WARN] Не вдалося зв'язатися з сервером: {e}. Працюю за кешем.")
            last_sync = now

        kill_blocked_processes(blocked)
        time.sleep(KILL_CHECK_INTERVAL_SEC)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
