# PC Control — Remotely block apps and websites on Windows PCs

*[Читати українською](README.md)*

A lightweight, self-hosted tool for a system administrator managing a fleet
of Windows PCs on a local network (a classroom, a computer lab, an office).
Lets you block or allow specific programs and specific websites from one web
dashboard — globally (all PCs), per group of PCs (e.g. "Room 1"), or for one
individual PC.

**Features:**
- 🖥️ Browser-based dashboard: list of all connected PCs, online/offline
  status, grouping and sorting.
- 🚫 Block programs by process name — the process is terminated within ~1
  second of launch.
- 🌐 Block websites by domain (via the `hosts` file).
- 👥 Groups of PCs with their own rules (separate from global and
  per-PC rules).
- 🔒 Restrict access to the dashboard itself to an allow-list of IPs.
- 📦 No Python installation required on client PCs (the agent can be
  bundled into a single `.exe` with PyInstaller) and starts up
  independently of which user is logged into Windows (via Task
  Scheduler, running as SYSTEM).

**Architecture (2 parts):**

- **server/** — the control dashboard. Runs on one "admin" PC (the one
  you manage everything from). Shows all connected PCs, and lets you
  block/allow programs — globally, per group, or per individual PC.
- **agent/** — a small program installed on every PC where you want to
  enforce blocking. Every few seconds it asks the server "what's
  currently blocked" and immediately terminates any forbidden processes.

How it works: the agent doesn't pre-emptively "prevent" a launch at the
OS level — instead, it terminates the process almost instantly (within
~1 second) if its name is on the blocked list. For 15–30 ordinary PCs
on a network, this is the simplest reliable approach that doesn't
require deep system integration.

## ⚠️ Before you use this (important, public repo)

Out of the box, this code is only safe to run if you:
1. Set your own `PC_CONTROL_API_KEY` — on both the server and every
   agent. The default value `change-me-please` in the code is just a
   placeholder, not a real password. If you don't change it, anyone on
   your local network could in theory control your PCs.
2. Only run the server on a trusted local network (don't expose port
   8765 to the public internet without extra protection — a VPN, or at
   minimum the built-in IP allow-list described below).
3. Understand that the agent forcibly kills processes and edits the
   system `hosts` file — only use this on PCs you have the right to
   administer (your own, or an organization's PCs with proper
   authorization).

The author is not responsible for use of this code outside of
legitimate administration of your own or an authorized infrastructure.

## 1. Install the server (on the admin PC)

```
cd server
pip install -r requirements.txt
set PC_CONTROL_API_KEY=some-long-secret-key
python app.py
```

The server starts on port 8765. Find this PC's local network IP
(`ipconfig`, usually something like `192.168.1.50`) — you'll need it for
the agents.

Open in a browser: `http://<admin-pc-ip>:8765` — that's the dashboard.

**Important:** make sure to set your own `PC_CONTROL_API_KEY` (a long
random string), otherwise anyone on the network could control your PCs
through the default placeholder `change-me-please`.

If Windows Firewall is active on the admin PC, allow inbound connections
on port 8765 (Windows Defender Firewall → Advanced settings → Inbound
Rules).

## 2. Install the agent (on each of the 15–30 PCs)

Copy the `agent/` folder to the PC and run:

```
cd agent
pip install -r requirements.txt
set PC_CONTROL_SERVER=http://<admin-pc-ip>:8765
set PC_CONTROL_API_KEY=the same key as on the server
pythonw agent.py
```

`pythonw` (not `python`) runs it without a visible console window.

### Autostart independent of the logged-in user (recommended)

The `agent/` folder includes a ready-made `install_agent.ps1` script
that does everything in one run: it registers a scheduled task that
triggers **"At system startup"** (not "at logon") and runs as
**SYSTEM** — meaning it works regardless of who (or whether anyone) is
logged into Windows, and restarts itself automatically if the process
ever exits.

1. Open `agent/install_agent.ps1` in a text editor and edit the 3
   variables at the top: `$ServerUrl` (the admin PC's address),
   `$ApiKey` (the same key as on the server), `$PythonExe` (the full
   path to your installed `pythonw.exe`).
2. Right-click the file → **"Run with PowerShell"** — make sure to do
   this as Administrator (or run from an elevated PowerShell console:
   `powershell -ExecutionPolicy Bypass -File install_agent.ps1`).
3. The script creates the machine-wide environment variables and the
   scheduled task, starts the agent immediately, and prints its status.

To confirm it worked: the PC should appear in the dashboard
(`http://<admin-pc-ip>:8765`).

To reinstall (e.g. after changing `$ServerUrl`) — just run the script
again; it removes the old task and creates a new one.

<details>
<summary>Manual setup via Task Scheduler (if you'd rather not use PowerShell)</summary>

1. Open **Task Scheduler**.
2. **Create Task** (not Basic Task):
   - General: name it "PCControlAgent", check **"Run whether user is
     logged on or not"**, set the user to **SYSTEM** ("Change User or
     Group" → type `SYSTEM`), check "Run with highest privileges".
   - Triggers: **At startup** (NOT "At log on" — otherwise it depends
     on a specific user).
   - Actions: Start a program →
     - Program: path to `pythonw.exe`
     - Arguments: path to `agent.py`
     - Start in: the agent's folder (so `agent_id.txt` is stored next
       to it)
   - Settings: check "If the task fails, restart every 1 minute",
     "Restart up to 999 times".
3. Set the `PC_CONTROL_SERVER` and `PC_CONTROL_API_KEY` environment
   variables **system-wide** (Control Panel → System → Advanced system
   settings → Environment Variables → System variables), since a task
   running as SYSTEM won't see variables set with a plain `set` in a
   user's console.
</details>

### Mass deployment to many PCs

To avoid doing this by hand 15–30 times:
- Bundle the agent into a single `.exe` (`pip install pyinstaller`,
  then `pyinstaller --onefile --noconsole agent.py`) — then target PCs
  don't need Python installed at all.
- Distribute the resulting `.exe` plus a small `.bat` script that
  creates the Task Scheduler task (`schtasks /create ...`) via a
  network share, a login script, or group policy, and run it on all
  PCs at once.

## 3. Usage

- Go to `http://<admin-pc-ip>:8765`.
- The top block shows the global list of blocked programs (applies
  immediately to every connected PC).
- Below that is the list of all PCs, marked online/offline. Click
  "manage" to block/allow a program on just that one PC.
- To **allow** a program again — just click the "✕" next to its name
  in the list.
- You can type a process name as `chrome` or `chrome.exe` — either
  works.

## Blocking websites

Works the same way as blocking programs — the dashboard has a separate
"Blocked sites" block (global, applies to all PCs) and one on each
PC's own page (applies only to it). Enter a domain, e.g. `youtube.com`
— it doesn't matter whether you include `https://` or `www.`, the
agent normalizes it automatically.

Technically this works via the `hosts` file on the client PC — the
agent appends blocked domains there so they "go nowhere". This:
- takes effect almost instantly (checked on every sync cycle, ~every 5
  sec);
- requires no certificates or proxies;
- blocks the whole domain (every page on it), not individual search
  keywords — blocking specific keywords in search requires a
  fundamentally different, much more complex approach (an
  HTTPS-decrypting proxy with a root certificate installed on every
  PC) — a separate, larger effort if you need it later.

**Important:** writing to `hosts` requires administrator/SYSTEM
privileges — if you set up autostart via `install_agent.ps1` (runs as
SYSTEM), this works automatically. If you run the agent manually in an
ordinary console without admin rights, you'll see a warning in the
console and sites won't get blocked.

If a site still opens after being blocked, the most common cause is
the browser caching the old page/DNS — restart the browser, or wait one
sync cycle (~5 sec) and try a new tab.

## PC groups

Each PC can be assigned to a group (e.g. "Room 1") on that PC's page in
the dashboard. Blocking rules apply at three levels, from broadest to
narrowest:

1. **Global** — applies to every PC at once.
2. **Group** — applies to every PC in that group (managed on the
   group's own page; a "manage group" link appears next to the group
   name on the main page).
3. **Individual PC** — applies only to it.

A rule takes effect if it exists at any of these levels — so removing a
rule that came from a group or globally has to be done on the
corresponding page (the group's, or the main page), not on the
individual PC's page.

## Restricting dashboard access by IP

To make the web dashboard (browser access) open only from specific IP
addresses — this does **not** affect agents (they keep connecting from
any PC via their API key; no need to reconfigure groups or PCs).

Before starting the server, set an environment variable with a
comma-separated list of allowed IPs:

```
set PC_CONTROL_ADMIN_IPS=192.168.1.10,192.168.1.20
python app.py
```

- If not set, the restriction is disabled — the dashboard is open to
  everyone on the network (as before).
- `127.0.0.1` (the server itself) always has access, regardless of the
  list, so you can't lock yourself out.
- If your PC's address changes (DHCP), it's best to set a static
  (reserved) IP for it on your router — otherwise you could lock
  yourself out after a router/PC reboot.

## Known limitations

- This is process-level blocking (`kill`), not access-control-level —
  a determined user could in theory rename the exe file to bypass it.
  For controlling ordinary users on your own PCs this is sufficient;
  defending against deliberate evasion needs a different layer
  (AppLocker/GPO) — ask if you need pointers.
- The agent should only ever terminate real user applications — the
  `NEVER_KILL` list in the code protects core system processes, but
  avoid adding system process names to the block rules.

## License

MIT — see [LICENSE](LICENSE).
