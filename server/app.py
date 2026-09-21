"""
Сервер централізованого керування блокуванням програм.

Запускається на "адмінському" ПК. Клієнтські ПК (агенти) стукаються
сюди по мережі, отримують список заблокованих програм і виконують
блокування локально.

Запуск:
    pip install -r requirements.txt
    python app.py

За замовчуванням сервер слухає на 0.0.0.0:8765 (доступний з локальної мережі).
"""

import os
import sqlite3
import time
import uuid
from datetime import datetime, timezone

from flask import Flask, g, jsonify, redirect, render_template_string, request, url_for

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(APP_DIR, "control.db")

# Простий спільний ключ для захисту API від чужих запитів у мережі.
# ЗМІНІТЬ це значення на своє перед розгортанням!
API_KEY = os.environ.get("PC_CONTROL_API_KEY", "change-me-please")

ONLINE_THRESHOLD_SEC = 20  # якщо heartbeat не було довше — вважаємо offline

# IP-адреси, яким дозволено відкривати веб-панель (браузером). Не стосується
# агентів — вони й далі можуть стукатись з будь-якого ПК, бо в них своя
# авторизація через API_KEY. Порожньо = обмеження вимкнено (доступ для всіх).
ADMIN_ALLOWED_IPS = {
    ip.strip() for ip in os.environ.get("PC_CONTROL_ADMIN_IPS", "").split(",") if ip.strip()
}

app = Flask(__name__)


@app.before_request
def restrict_admin_panel_access():
    # API-запити від агентів не обмежуємо за IP — вони й так захищені X-API-Key
    if request.path.startswith("/api/"):
        return
    if not ADMIN_ALLOWED_IPS:
        return  # обмеження не налаштоване — доступ відкритий, як і раніше
    client_ip = request.remote_addr
    if client_ip in ADMIN_ALLOWED_IPS or client_ip == "127.0.0.1":
        return
    return f"Доступ заборонено: IP {client_ip} не в списку дозволених.", 403


# --------------------------------------------------------------------------- #
# База даних
# --------------------------------------------------------------------------- #

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS agents (
            id TEXT PRIMARY KEY,
            hostname TEXT,
            ip TEXT,
            last_seen REAL
        );

        CREATE TABLE IF NOT EXISTS global_rules (
            process_name TEXT PRIMARY KEY
        );

        CREATE TABLE IF NOT EXISTS agent_rules (
            agent_id TEXT,
            process_name TEXT,
            PRIMARY KEY (agent_id, process_name)
        );

        CREATE TABLE IF NOT EXISTS global_domain_rules (
            domain TEXT PRIMARY KEY
        );

        CREATE TABLE IF NOT EXISTS agent_domain_rules (
            agent_id TEXT,
            domain TEXT,
            PRIMARY KEY (agent_id, domain)
        );

        CREATE TABLE IF NOT EXISTS group_rules (
            group_name TEXT,
            process_name TEXT,
            PRIMARY KEY (group_name, process_name)
        );

        CREATE TABLE IF NOT EXISTS group_domain_rules (
            group_name TEXT,
            domain TEXT,
            PRIMARY KEY (group_name, domain)
        );
        """
    )
    # Міграція: додаємо колонку group_name, якщо БД створена старою версією
    cols = [r[1] for r in conn.execute("PRAGMA table_info(agents)")]
    if "group_name" not in cols:
        conn.execute("ALTER TABLE agents ADD COLUMN group_name TEXT DEFAULT ''")
    conn.commit()
    conn.close()


# --------------------------------------------------------------------------- #
# Допоміжні функції
# --------------------------------------------------------------------------- #

def require_api_key():
    key = request.headers.get("X-API-Key") or request.args.get("key")
    if key != API_KEY:
        return False
    return True


def norm(name: str) -> str:
    """Нормалізуємо назву процесу: без .exe, у нижньому регістрі."""
    name = name.strip().lower()
    if name.endswith(".exe"):
        name = name[:-4]
    return name


def norm_domain(domain: str) -> str:
    """Нормалізуємо домен: без протоколу/шляху/www., у нижньому регістрі."""
    d = domain.strip().lower()
    d = d.replace("https://", "").replace("http://", "")
    d = d.split("/", 1)[0]
    d = d.split(":", 1)[0]  # без порту
    if d.startswith("www."):
        d = d[4:]
    return d.rstrip(".")


# --------------------------------------------------------------------------- #
# API для агентів (клієнтських ПК)
# --------------------------------------------------------------------------- #

@app.route("/api/heartbeat", methods=["POST"])
def api_heartbeat():
    if not require_api_key():
        return jsonify({"error": "unauthorized"}), 401

    data = request.get_json(force=True)
    agent_id = data.get("agent_id")
    hostname = data.get("hostname", "unknown")
    if not agent_id:
        return jsonify({"error": "agent_id required"}), 400

    db = get_db()
    ip = request.remote_addr
    now = time.time()
    db.execute(
        """
        INSERT INTO agents (id, hostname, ip, last_seen)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET hostname=?, ip=?, last_seen=?
        """,
        (agent_id, hostname, ip, now, hostname, ip, now),
    )
    db.commit()
    return jsonify({"ok": True})


@app.route("/api/rules/<agent_id>", methods=["GET"])
def api_rules(agent_id):
    if not require_api_key():
        return jsonify({"error": "unauthorized"}), 401

    db = get_db()
    a = db.execute("SELECT group_name FROM agents WHERE id=?", (agent_id,)).fetchone()
    group_name = a["group_name"] if a else None

    global_rules = [r["process_name"] for r in db.execute("SELECT process_name FROM global_rules")]
    group_rules = []
    if group_name:
        group_rules = [
            r["process_name"]
            for r in db.execute("SELECT process_name FROM group_rules WHERE group_name=?", (group_name,))
        ]
    agent_rules = [
        r["process_name"]
        for r in db.execute("SELECT process_name FROM agent_rules WHERE agent_id=?", (agent_id,))
    ]
    blocked = sorted(set(global_rules) | set(group_rules) | set(agent_rules))
    return jsonify({"blocked": blocked})


@app.route("/api/site-rules/<agent_id>", methods=["GET"])
def api_site_rules(agent_id):
    if not require_api_key():
        return jsonify({"error": "unauthorized"}), 401

    db = get_db()
    a = db.execute("SELECT group_name FROM agents WHERE id=?", (agent_id,)).fetchone()
    group_name = a["group_name"] if a else None

    global_domains = [r["domain"] for r in db.execute("SELECT domain FROM global_domain_rules")]
    group_domains = []
    if group_name:
        group_domains = [
            r["domain"]
            for r in db.execute("SELECT domain FROM group_domain_rules WHERE group_name=?", (group_name,))
        ]
    agent_domains = [
        r["domain"]
        for r in db.execute("SELECT domain FROM agent_domain_rules WHERE agent_id=?", (agent_id,))
    ]
    blocked = sorted(set(global_domains) | set(group_domains) | set(agent_domains))
    return jsonify({"blocked_domains": blocked})


# --------------------------------------------------------------------------- #
# Веб-панель адміністратора
# --------------------------------------------------------------------------- #

PAGE_TEMPLATE = """
<!doctype html>
<html lang="uk">
<head>
<meta charset="utf-8">
<title>Керування ПК</title>
<style>
  body { font-family: Arial, sans-serif; margin: 2rem; background: #f5f5f5; }
  h1, h2 { color: #222; }
  table { border-collapse: collapse; width: 100%; background: white; }
  th, td { border: 1px solid #ddd; padding: 8px 12px; text-align: left; }
  th { background: #333; color: white; }
  .online { color: green; font-weight: bold; }
  .offline { color: #999; }
  .card { background: white; padding: 1rem 1.5rem; border-radius: 8px; margin-bottom: 1.5rem; box-shadow: 0 1px 3px rgba(0,0,0,0.1);}
  form.inline { display: inline; }
  input[type=text] { padding: 6px; width: 200px; }
  button { padding: 6px 14px; cursor: pointer; }
  a { color: #06c; text-decoration: none; }
  .tag { display:inline-block; background:#eee; border-radius:4px; padding:2px 8px; margin:2px; }
  .tag form { display:inline; }
  .tag button { padding: 0 6px; margin-left:4px; }
</style>
</head>
<body>
<h1>Панель керування ПК</h1>
{{ body|safe }}
</body>
</html>
"""


@app.route("/")
def index():
    db = get_db()
    sort = request.args.get("sort", "group")  # group | status | name | last_seen
    agents = db.execute("SELECT * FROM agents").fetchall()
    now = time.time()

    def is_online(a):
        return (now - a["last_seen"]) < ONLINE_THRESHOLD_SEC

    if sort == "status":
        agents = sorted(agents, key=lambda a: (not is_online(a), (a["hostname"] or "").lower()))
    elif sort == "name":
        agents = sorted(agents, key=lambda a: (a["hostname"] or "").lower())
    elif sort == "last_seen":
        agents = sorted(agents, key=lambda a: -a["last_seen"])
    else:  # group (default)
        agents = sorted(agents, key=lambda a: ((a["group_name"] or "").lower(), (a["hostname"] or "").lower()))

    def row_html(a):
        status = "online" if is_online(a) else "offline"
        status_txt = "🟢 онлайн" if status == "online" else "⚪ офлайн"
        last_seen_str = datetime.fromtimestamp(a["last_seen"], tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        return f"""
        <tr>
          <td>{a['hostname']}</td>
          <td>{a['ip']}</td>
          <td class="{status}">{status_txt}</td>
          <td>{last_seen_str}</td>
          <td><a href="/agent/{a['id']}">керувати</a></td>
        </tr>
        """

    if sort in ("status", "name", "last_seen"):
        rows = "".join(row_html(a) for a in agents)
        agents_html = f"""
        <table>
          <tr><th>Ім'я ПК</th><th>IP</th><th>Статус</th><th>Останній зв'язок</th><th></th></tr>
          {rows or '<tr><td colspan="5"><i>Ще жоден агент не підключився</i></td></tr>'}
        </table>
        """
    else:
        # групування
        groups = {}
        for a in agents:
            g = a["group_name"] or "Без групи"
            groups.setdefault(g, []).append(a)
        agents_html = ""
        for g in sorted(groups.keys(), key=lambda x: (x == "Без групи", x.lower())):
            rows = "".join(row_html(a) for a in groups[g])
            group_link = f'<a href="/group/{g}">керувати групою</a>' if g != "Без групи" else ""
            agents_html += f"""
            <h3>{g} ({len(groups[g])}) {group_link}</h3>
            <table>
              <tr><th>Ім'я ПК</th><th>IP</th><th>Статус</th><th>Останній зв'язок</th><th></th></tr>
              {rows}
            </table>
            """
        if not agents:
            agents_html = "<p><i>Ще жоден агент не підключився</i></p>"

    sort_links = f"""
    <p>
      Сортувати:
      <a href="/?sort=group">за групою</a> |
      <a href="/?sort=name">за іменем</a> |
      <a href="/?sort=status">за статусом (онлайн спочатку)</a> |
      <a href="/?sort=last_seen">за останнім зв'язком</a>
    </p>
    """

    global_rules = [r["process_name"] for r in db.execute("SELECT process_name FROM global_rules")]
    global_tags = ""
    for pn in sorted(global_rules):
        global_tags += f"""
        <span class="tag">{pn}
          <form class="inline" method="post" action="/global/remove">
            <input type="hidden" name="process_name" value="{pn}">
            <button title="Дозволити знову">✕</button>
          </form>
        </span>
        """

    global_domains = [r["domain"] for r in db.execute("SELECT domain FROM global_domain_rules")]
    global_domain_tags = ""
    for d in sorted(global_domains):
        global_domain_tags += f"""
        <span class="tag">{d}
          <form class="inline" method="post" action="/domain/global/remove">
            <input type="hidden" name="domain" value="{d}">
            <button title="Дозволити знову">✕</button>
          </form>
        </span>
        """

    body = f"""
    <div class="card">
      <h2>Глобально заблоковані програми (діють на ВСІ ПК)</h2>
      <div>{global_tags or '<i>немає</i>'}</div>
      <form method="post" action="/global/add">
        <input type="text" name="process_name" placeholder="напр. chrome або chrome.exe" required>
        <button>Заблокувати на всіх ПК</button>
      </form>
    </div>

    <div class="card">
      <h2>Глобально заблоковані сайти (діють на ВСІ ПК)</h2>
      <div>{global_domain_tags or '<i>немає</i>'}</div>
      <form method="post" action="/domain/global/add">
        <input type="text" name="domain" placeholder="напр. youtube.com" required>
        <button>Заблокувати на всіх ПК</button>
      </form>
    </div>

    <div class="card">
      <h2>Підключені ПК ({len(agents)})</h2>
      {sort_links}
      {agents_html}
    </div>
    """
    return render_template_string(PAGE_TEMPLATE, body=body)


@app.route("/global/add", methods=["POST"])
def global_add():
    pn = norm(request.form["process_name"])
    db = get_db()
    db.execute("INSERT OR IGNORE INTO global_rules (process_name) VALUES (?)", (pn,))
    db.commit()
    return redirect(url_for("index"))


@app.route("/global/remove", methods=["POST"])
def global_remove():
    pn = norm(request.form["process_name"])
    db = get_db()
    db.execute("DELETE FROM global_rules WHERE process_name=?", (pn,))
    db.commit()
    return redirect(url_for("index"))


@app.route("/agent/<agent_id>")
def agent_page(agent_id):
    db = get_db()
    a = db.execute("SELECT * FROM agents WHERE id=?", (agent_id,)).fetchone()
    if not a:
        return "ПК не знайдено", 404

    own_rules = [r["process_name"] for r in db.execute("SELECT process_name FROM agent_rules WHERE agent_id=?", (agent_id,))]
    global_rules = [r["process_name"] for r in db.execute("SELECT process_name FROM global_rules")]
    group_rules = []
    if a["group_name"]:
        group_rules = [
            r["process_name"]
            for r in db.execute("SELECT process_name FROM group_rules WHERE group_name=?", (a["group_name"],))
        ]

    own_tags = ""
    for pn in sorted(own_rules):
        own_tags += f"""
        <span class="tag">{pn}
          <form class="inline" method="post" action="/agent/{agent_id}/remove">
            <input type="hidden" name="process_name" value="{pn}">
            <button title="Дозволити знову">✕</button>
          </form>
        </span>
        """

    global_list = ", ".join(sorted(global_rules)) or "немає"
    group_list = ", ".join(sorted(group_rules)) or "немає"

    own_domains = [r["domain"] for r in db.execute("SELECT domain FROM agent_domain_rules WHERE agent_id=?", (agent_id,))]
    global_domains = [r["domain"] for r in db.execute("SELECT domain FROM global_domain_rules")]
    group_domains = []
    if a["group_name"]:
        group_domains = [
            r["domain"]
            for r in db.execute("SELECT domain FROM group_domain_rules WHERE group_name=?", (a["group_name"],))
        ]

    own_domain_tags = ""
    for d in sorted(own_domains):
        own_domain_tags += f"""
        <span class="tag">{d}
          <form class="inline" method="post" action="/domain/agent/{agent_id}/remove">
            <input type="hidden" name="domain" value="{d}">
            <button title="Дозволити знову">✕</button>
          </form>
        </span>
        """

    global_domain_list = ", ".join(sorted(global_domains)) or "немає"
    group_domain_list = ", ".join(sorted(group_domains)) or "немає"

    group_link = f' | <a href="/group/{a["group_name"]}">керувати групою "{a["group_name"]}"</a>' if a["group_name"] else ""

    body = f"""
    <p><a href="/">&larr; До списку ПК</a></p>
    <div class="card">
      <h2>{a['hostname']} <small>({a['ip']})</small></h2>
      <p>Група: <b>{a['group_name'] or 'без групи'}</b>{group_link}</p>
      <form method="post" action="/agent/{agent_id}/set-group">
        <input type="text" name="group_name" placeholder="напр. Кабінет 1" value="{a['group_name'] or ''}">
        <button>Зберегти групу</button>
      </form>
    </div>
    <div class="card">
      <p>Глобально заблоковано (на всіх ПК, тут прибрати не можна): {global_list}</p>
      <p>Заблоковано через групу (тут прибрати не можна, керується на сторінці групи): {group_list}</p>
      <h3>Заблоковано тільки на цьому ПК</h3>
      <div>{own_tags or '<i>немає</i>'}</div>
      <form method="post" action="/agent/{agent_id}/add">
        <input type="text" name="process_name" placeholder="напр. steam або steam.exe" required>
        <button>Заблокувати на цьому ПК</button>
      </form>
    </div>

    <div class="card">
      <h2>Сайти для {a['hostname']}</h2>
      <p>Глобально заблоковані сайти (на всіх ПК, тут прибрати не можна): {global_domain_list}</p>
      <p>Заблоковано через групу (тут прибрати не можна, керується на сторінці групи): {group_domain_list}</p>
      <h3>Заблоковано тільки на цьому ПК</h3>
      <div>{own_domain_tags or '<i>немає</i>'}</div>
      <form method="post" action="/domain/agent/{agent_id}/add">
        <input type="text" name="domain" placeholder="напр. youtube.com" required>
        <button>Заблокувати на цьому ПК</button>
      </form>
    </div>
    """
    return render_template_string(PAGE_TEMPLATE, body=body)


@app.route("/group/<group_name>")
def group_page(group_name):
    db = get_db()
    members = db.execute(
        "SELECT hostname FROM agents WHERE group_name=? ORDER BY hostname", (group_name,)
    ).fetchall()

    own_rules = [r["process_name"] for r in db.execute("SELECT process_name FROM group_rules WHERE group_name=?", (group_name,))]
    own_domains = [r["domain"] for r in db.execute("SELECT domain FROM group_domain_rules WHERE group_name=?", (group_name,))]
    global_rules = [r["process_name"] for r in db.execute("SELECT process_name FROM global_rules")]
    global_domains = [r["domain"] for r in db.execute("SELECT domain FROM global_domain_rules")]

    own_tags = ""
    for pn in sorted(own_rules):
        own_tags += f"""
        <span class="tag">{pn}
          <form class="inline" method="post" action="/group/{group_name}/remove">
            <input type="hidden" name="process_name" value="{pn}">
            <button title="Дозволити знову">✕</button>
          </form>
        </span>
        """

    own_domain_tags = ""
    for d in sorted(own_domains):
        own_domain_tags += f"""
        <span class="tag">{d}
          <form class="inline" method="post" action="/group/{group_name}/domain/remove">
            <input type="hidden" name="domain" value="{d}">
            <button title="Дозволити знову">✕</button>
          </form>
        </span>
        """

    members_list = ", ".join(m["hostname"] for m in members) or "немає ПК у цій групі"

    body = f"""
    <p><a href="/">&larr; До списку ПК</a></p>
    <div class="card">
      <h2>Група: {group_name}</h2>
      <p>ПК у групі ({len(members)}): {members_list}</p>
    </div>

    <div class="card">
      <h2>Програми, заблоковані для всієї групи "{group_name}"</h2>
      <p>Глобально заблоковано (на всіх ПК, тут прибрати не можна): {", ".join(sorted(global_rules)) or "немає"}</p>
      <div>{own_tags or '<i>немає</i>'}</div>
      <form method="post" action="/group/{group_name}/add">
        <input type="text" name="process_name" placeholder="напр. steam або steam.exe" required>
        <button>Заблокувати для групи</button>
      </form>
    </div>

    <div class="card">
      <h2>Сайти, заблоковані для всієї групи "{group_name}"</h2>
      <p>Глобально заблоковано (на всіх ПК, тут прибрати не можна): {", ".join(sorted(global_domains)) or "немає"}</p>
      <div>{own_domain_tags or '<i>немає</i>'}</div>
      <form method="post" action="/group/{group_name}/domain/add">
        <input type="text" name="domain" placeholder="напр. youtube.com" required>
        <button>Заблокувати для групи</button>
      </form>
    </div>
    """
    return render_template_string(PAGE_TEMPLATE, body=body)


@app.route("/group/<group_name>/add", methods=["POST"])
def group_add(group_name):
    pn = norm(request.form["process_name"])
    db = get_db()
    db.execute("INSERT OR IGNORE INTO group_rules (group_name, process_name) VALUES (?, ?)", (group_name, pn))
    db.commit()
    return redirect(url_for("group_page", group_name=group_name))


@app.route("/group/<group_name>/remove", methods=["POST"])
def group_remove(group_name):
    pn = norm(request.form["process_name"])
    db = get_db()
    db.execute("DELETE FROM group_rules WHERE group_name=? AND process_name=?", (group_name, pn))
    db.commit()
    return redirect(url_for("group_page", group_name=group_name))


@app.route("/group/<group_name>/domain/add", methods=["POST"])
def group_domain_add(group_name):
    d = norm_domain(request.form["domain"])
    db = get_db()
    db.execute("INSERT OR IGNORE INTO group_domain_rules (group_name, domain) VALUES (?, ?)", (group_name, d))
    db.commit()
    return redirect(url_for("group_page", group_name=group_name))


@app.route("/group/<group_name>/domain/remove", methods=["POST"])
def group_domain_remove(group_name):
    d = norm_domain(request.form["domain"])
    db = get_db()
    db.execute("DELETE FROM group_domain_rules WHERE group_name=? AND domain=?", (group_name, d))
    db.commit()
    return redirect(url_for("group_page", group_name=group_name))


@app.route("/agent/<agent_id>/set-group", methods=["POST"])
def agent_set_group(agent_id):
    group_name = request.form.get("group_name", "").strip()
    db = get_db()
    db.execute("UPDATE agents SET group_name=? WHERE id=?", (group_name, agent_id))
    db.commit()
    return redirect(url_for("agent_page", agent_id=agent_id))


@app.route("/domain/global/add", methods=["POST"])
def domain_global_add():
    d = norm_domain(request.form["domain"])
    db = get_db()
    db.execute("INSERT OR IGNORE INTO global_domain_rules (domain) VALUES (?)", (d,))
    db.commit()
    return redirect(url_for("index"))


@app.route("/domain/global/remove", methods=["POST"])
def domain_global_remove():
    d = norm_domain(request.form["domain"])
    db = get_db()
    db.execute("DELETE FROM global_domain_rules WHERE domain=?", (d,))
    db.commit()
    return redirect(url_for("index"))


@app.route("/domain/agent/<agent_id>/add", methods=["POST"])
def domain_agent_add(agent_id):
    d = norm_domain(request.form["domain"])
    db = get_db()
    db.execute("INSERT OR IGNORE INTO agent_domain_rules (agent_id, domain) VALUES (?, ?)", (agent_id, d))
    db.commit()
    return redirect(url_for("agent_page", agent_id=agent_id))


@app.route("/domain/agent/<agent_id>/remove", methods=["POST"])
def domain_agent_remove(agent_id):
    d = norm_domain(request.form["domain"])
    db = get_db()
    db.execute("DELETE FROM agent_domain_rules WHERE agent_id=? AND domain=?", (agent_id, d))
    db.commit()
    return redirect(url_for("agent_page", agent_id=agent_id))


@app.route("/agent/<agent_id>/add", methods=["POST"])
def agent_add(agent_id):
    pn = norm(request.form["process_name"])
    db = get_db()
    db.execute("INSERT OR IGNORE INTO agent_rules (agent_id, process_name) VALUES (?, ?)", (agent_id, pn))
    db.commit()
    return redirect(url_for("agent_page", agent_id=agent_id))


@app.route("/agent/<agent_id>/remove", methods=["POST"])
def agent_remove(agent_id):
    pn = norm(request.form["process_name"])
    db = get_db()
    db.execute("DELETE FROM agent_rules WHERE agent_id=? AND process_name=?", (agent_id, pn))
    db.commit()
    return redirect(url_for("agent_page", agent_id=agent_id))


if __name__ == "__main__":
    init_db()
    print(f"API_KEY = {API_KEY}")
    print("Не забудьте змінити ключ через змінну середовища PC_CONTROL_API_KEY!")
    app.run(host="0.0.0.0", port=8765, debug=False)
