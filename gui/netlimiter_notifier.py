#!/usr/bin/python3
"""Receives requests from netlimiterd via stdin and displays interactive notifications via D-Bus."""
import json
import os
import signal
import socket
import subprocess
import sys
import threading

import gi

gi.require_version("Gio", "2.0")
gi.require_version("Gtk", "4.0")
from gi.repository import Gio, GLib, Gtk

SOCKET_CANDIDATES = (
    "/run/netlimiter/netlimiter.sock",
    "/tmp/netlimiter.sock",
    os.path.join(os.environ.get("XDG_RUNTIME_DIR", "/nonexistent"), "netlimiter.sock"),
)

NOTIFY_BUS = "org.freedesktop.Notifications"
NOTIFY_PATH = "/org/freedesktop/Notifications"
NOTIFY_IFACE = "org.freedesktop.Notifications"


def log(msg: str) -> None:
    print(f"[notifier] {msg}", file=sys.stderr, flush=True)


def send_request(payload: dict) -> dict:
    last_err = "socket unavailable"
    for path in SOCKET_CANDIDATES:
        if not os.path.exists(path):
            continue
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(3.0)
                sock.connect(path)
                sock.sendall((json.dumps(payload) + "\n").encode())
                data = b""
                while b"\n" not in data:
                    chunk = sock.recv(65536)
                    if not chunk:
                        break
                    data += chunk
            return json.loads(data.decode().split("\n", 1)[0])
        except (OSError, ValueError) as exc:
            last_err = str(exc)
    return {"ok": False, "error": last_err}


class Notifier:
    def __init__(self):
        self.bus = Gio.bus_get_sync(Gio.BusType.SESSION, None)
        self.bus.signal_subscribe(
            None, NOTIFY_IFACE, "ActionInvoked", NOTIFY_PATH, None,
            Gio.DBusSignalFlags.NONE, self.on_action,
        )
        self.bus.signal_subscribe(
            None, NOTIFY_IFACE, "NotificationClosed", NOTIFY_PATH, None,
            Gio.DBusSignalFlags.NONE, self.on_closed,
        )
        self.pending: dict[int, tuple[str, str]] = {}
        self.app_icons = self._load_system_icons()

    def _load_system_icons(self) -> dict:
        mapping = {}
        try:
            for info in Gio.AppInfo.get_all():
                executable = info.get_executable()
                icon = info.get_icon()
                if executable and icon:
                    base_exe = os.path.basename(executable).lower()
                    mapping[base_exe] = icon.to_string() if hasattr(icon, "to_string") else "application-x-executable"
                    app_id = info.get_id()
                    if app_id:
                        mapping[app_id.lower().split(".")[0]] = mapping[base_exe]
        except Exception:
            pass
        return mapping

    def _get_app_icon(self, exe: str) -> str:
        base_exe = os.path.basename(exe).lower()
        if base_exe in self.app_icons:
            return self.app_icons[base_exe]
        for k, v in self.app_icons.items():
            if k in base_exe or base_exe in k:
                return v
        return "applications-internet-symbolic"

    def _notify(self, summary, body, actions, urgency, timeout, replaces=0, icon="network-wired-symbolic"):
        hints = {
            "urgency": GLib.Variant("y", urgency),
            "category": GLib.Variant("s", "network.router"),
            "desktop-entry": GLib.Variant("s", "netlimiter-linux"),
        }
        params = GLib.Variant(
            "(susssasa{sv}i)",
            ("NetLimiter-Linux", replaces, icon, summary, body, actions, hints, timeout),
        )
        try:
            result = self.bus.call_sync(
                NOTIFY_BUS, NOTIFY_PATH, NOTIFY_IFACE, "Notify", params, None,
                Gio.DBusCallFlags.NONE, 5000, None,
            )
            return result.unpack()[0]
        except GLib.Error as exc:
            log(f"D-Bus error: {exc}")
            return None

    def notify_new_app(self, exe: str, name: str):
        if any(e == exe for e, _ in self.pending.values()):
            return

        icon_name = self._get_app_icon(exe)

        summary = f"<b>Network Alert:</b> {name}"
        body = f"Application is trying to access the internet:\n<code>{exe}</code>\n\nPlease select an action:"

        nid = self._notify(
            summary,
            body,
            ["block", "🚫 Block", "allow", "✅ Allow", "limit", "⚡ Limit Speed"],
            urgency=2,
            timeout=-1,
            icon=icon_name,
        )
        if nid is not None:
            self.pending[nid] = (exe, name)
            log(f"shown id={nid} for {exe} with icon {icon_name}")

    def on_action(self, _conn, _sender, _path, _iface, _signal, params):
        nid, action = params.unpack()
        entry = self.pending.pop(nid, None)
        if not entry:
            return
        exe, name = entry
        log(f"action={action} exe={exe}")
        threading.Thread(
            target=self._handle_decision, args=(nid, exe, name, action), daemon=True
        ).start()

    def on_closed(self, _conn, _sender, _path, _iface, _signal, params):
        nid, reason = params.unpack()
        entry = self.pending.pop(nid, None)
        if entry:
            log(f"closed without decision (reason={reason}) exe={entry[0]}")

    def _handle_decision(self, nid: int, exe: str, name: str, action: str):
        if action == "block":
            resp = send_request({"cmd": "set_rule", "exe": exe, "action": "block", "enabled": True})
            done = f"🚫 Blocked: {name}"
        elif action == "allow":
            resp = send_request({"cmd": "set_rule", "exe": exe, "action": "allow", "enabled": True})
            done = f"✅ Allowed: {name}"
        elif action == "limit":
            try:
                subprocess.Popen(
                    ["netlimiter-linux", "--select", exe],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )
                resp = {"ok": True}
            except OSError as exc:
                resp = {"ok": False, "error": f"Failed to open GUI: {exc}"}
            done = f"⚡ Opening GUI to limit {name}"
        else:
            return

        if resp.get("ok"):
            log(f"{action} OK for {exe}")
            GLib.idle_add(self._show_result, nid, done, "")
        else:
            err = resp.get("error", "unknown error")
            log(f"{action} FAILED for {exe}: {err}")
            GLib.idle_add(self._show_result, nid, f"⚠️ Failed to apply action for {name}", str(err))

    def _show_result(self, nid: int, summary: str, body: str):
        self._notify(summary, body, [], urgency=1, timeout=4000, replaces=nid, icon="emblem-default-symbolic")
        return False


def read_stdin(loop: GLib.MainLoop, notifier: Notifier):
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        if msg.get("type") == "new_app" and msg.get("exe"):
            GLib.idle_add(notifier.notify_new_app, msg["exe"], msg.get("name", "unknown"))
    GLib.idle_add(loop.quit)


def main() -> int:
    loop = GLib.MainLoop()
    notifier = Notifier()
    GLib.unix_signal_add(GLib.PRIORITY_DEFAULT, signal.SIGTERM, loop.quit)
    threading.Thread(target=read_stdin, args=(loop, notifier), daemon=True).start()
    log("ready")
    loop.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
