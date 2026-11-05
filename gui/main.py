#!/usr/bin/python3
"""NetLimiter-Linux - GTK4 / libadwaita front-end (Complete Edition with Autostart & Privacy Policy)."""
import json
import os
import socket
import subprocess
import sys
import threading
from pathlib import Path

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gdk, Gio, GLib, GObject, Gtk, Pango

SOCKET_CANDIDATES = (
    "/run/netlimiter/netlimiter.sock",
    "/tmp/netlimiter.sock",
    os.path.join(os.environ.get("XDG_RUNTIME_DIR", "/nonexistent"), "netlimiter.sock"),
    str(Path.home() / ".cache/netlimiter.sock"),
)

CSS = """
.nl-toolbar { padding: 6px 10px; background: rgba(0, 0, 0, 0.02); border-bottom: 1px solid rgba(255, 255, 255, 0.08); }
.nl-table cell { padding: 4px 6px; }
.nl-table row:nth-child(even) { background-color: rgba(255, 255, 255, 0.02); }
.nl-table row:nth-child(odd) { background-color: transparent; }
.nl-table row:hover { background-color: rgba(255, 255, 255, 0.06); }
.nl-table row:selected { background-color: rgba(53, 132, 228, 0.3); }

.nl-down { color: #57e389; font-weight: 600; font-size: 0.85em; }
.nl-up { color: #ff7800; font-weight: 600; font-size: 0.85em; }

.rule-dot-blocked { color: #ff5555; font-size: 1.1em; }
.rule-dot-limited { color: #f9c440; font-size: 1.1em; }
.rule-dot-allowed { color: #57e389; font-size: 1.1em; }
.rule-dot-none    { color: rgba(255, 255, 255, 0.2); font-size: 1.1em; }

.nl-status { padding: 6px 14px; font-size: 0.9em; border-top: 1px solid rgba(255, 255, 255, 0.08); }
.nl-stat { font-feature-settings: "tnum"; font-size: 0.85em; }
.nl-pause-on  { background: #26a269; color: white; font-weight: bold; border-radius: 6px; padding: 4px 10px; }
.nl-pause-off { background: #e01b24; color: white; font-weight: bold; border-radius: 6px; padding: 4px 10px; }
.sidebar-frame { background: rgba(255, 255, 255, 0.015); border-left: 1px solid rgba(255, 255, 255, 0.08); }
""".encode("utf-8")

STRINGS = {
    "title": "NetLimiter-Linux",
    "subtitle": "Monitor and Control Network Traffic",
    "lock_off": "Lock Network",
    "lock_on": "Network Locked",
    "running": "Running",
    "paused": "Paused",
    "clear_rules": "Clear All Rules",
    "autostart": "Start with System",
    "privacy": "Privacy Policy",
    "about": "About App",
    "search": "Search app or path...",
    "active_only": "Active Only",
    "block": "Block",
    "allow": "Allow",
    "limit": "Limit",
    "remove_rule": "Remove Rule",
    "app_name": "App Name",
    "down": "⬇ DL",
    "up": "⬆ UL",
    "down_limit": "DL.L",
    "up_limit": "UL.L",
    "rule": "⚙",
    "conns": "🔗",
    "total_down": "Tot ⬇",
    "total_up": "Tot ⬆",
    "ip_panel_title": "🔗 Connections & IPs",
    "show_listen": "Show LISTEN",
    "dest_ip": "Destination (IP)",
    "proto": "Proto",
    "state": "State",
    "service_offline": "Service Disconnected",
    "start_service": "Start Service",
    "apply": "Apply",
    "down_kb": "Download (KB/s)",
    "up_kb": "Upload (KB/s)",
    "zero_hint": "0 = No Limit",
    "root": "Root",
    "no_root": "Non-Root",
    "privacy_title": "Privacy Policy - NetLimiter-Linux",
    "privacy_text": (
        "NetLimiter-Linux is a local-first network monitoring and management tool.\n\n"
        "• 100% Local Processing: All traffic analysis, rule enforcement, and connection tracking are performed entirely on your local machine using nftables and local sockets.\n"
        "• No Data Collection: We do not collect, store, transmit, or share any personal data, telemetry, logs, browsing history, or IP addresses with any third-party servers.\n"
        "• All Rights Reserved: Unauthorized copying, modification, or redistribution of this software is strictly prohibited.\n\n"
        "Your privacy and data security are completely guaranteed by design."
    ),
}

# ---------------------------------------------------------------- Tray Integration
SNI_IFACE = "org.kde.StatusNotifierItem"
SNI_PATH = "/StatusNotifierItem"
WATCHER_NAME = "org.kde.StatusNotifierWatcher"
WATCHER_PATH = "/StatusNotifierWatcher"
MENU_IFACE = "com.canonical.dbusmenu"
MENU_PATH = "/MenuBar"

SNI_XML = """
<node>
  <interface name="org.kde.StatusNotifierItem">
    <property name="Category" type="s" access="read"/>
    <property name="Id" type="s" access="read"/>
    <property name="Title" type="s" access="read"/>
    <property name="Status" type="s" access="read"/>
    <property name="WindowId" type="u" access="read"/>
    <property name="IconName" type="s" access="read"/>
    <property name="IconPixmap" type="a(iiay)" access="read"/>
    <property name="OverlayIconName" type="s" access="read"/>
    <property name="OverlayIconPixmap" type="a(iiay)" access="read"/>
    <property name="AttentionIconName" type="s" access="read"/>
    <property name="AttentionIconPixmap" type="a(iiay)" access="read"/>
    <property name="AttentionMovieName" type="s" access="read"/>
    <property name="ToolTip" type="(sa(iiay)ss)" access="read"/>
    <property name="ItemIsMenu" type="b" access="read"/>
    <property name="Menu" type="o" access="read"/>
    <method name="ContextMenu"><arg type="i" direction="in"/><arg type="i" direction="in"/></method>
    <method name="Activate"><arg type="i" direction="in"/><arg type="i" direction="in"/></method>
    <method name="SecondaryActivate"><arg type="i" direction="in"/><arg type="i" direction="in"/></method>
    <method name="Scroll"><arg type="i" direction="in"/><arg type="s" direction="in"/></method>
    <signal name="NewTitle"/>
    <signal name="NewIcon"/>
    <signal name="NewAttentionIcon"/>
    <signal name="NewOverlayIcon"/>
    <signal name="NewToolTip"/>
    <signal name="NewStatus"><arg type="s"/></signal>
  </interface>
</node>
"""

MENU_XML = """
<node>
  <interface name="com.canonical.dbusmenu">
    <property name="Version" type="u" access="read"/>
    <property name="TextDirection" type="s" access="read"/>
    <property name="Status" type="s" access="read"/>
    <property name="IconThemePath" type="as" access="read"/>
    <method name="GetLayout">
      <arg type="i" direction="in"/><arg type="i" direction="in"/><arg type="as" direction="in"/>
      <arg type="u" direction="out"/><arg type="(ia{sv}av)" direction="out"/>
    </method>
    <method name="GetGroupProperties">
      <arg type="ai" direction="in"/><arg type="as" direction="in"/>
      <arg type="a(ia{sv})" direction="out"/>
    </method>
    <method name="GetProperty">
      <arg type="i" direction="in"/><arg type="s" direction="in"/><arg type="v" direction="out"/>
    </method>
    <method name="Event">
      <arg type="i" direction="in"/><arg type="s" direction="in"/><arg type="v" direction="in"/><arg type="u" direction="in"/>
    </method>
    <method name="EventGroup">
      <arg type="a(isvu)" direction="in"/><arg type="ai" direction="out"/>
    </method>
    <method name="AboutToShow"><arg type="i" direction="in"/><arg type="b" direction="out"/></method>
    <method name="AboutToShowGroup">
      <arg type="ai" direction="in"/><arg type="ai" direction="out"/><arg type="ai" direction="out"/>
    </method>
    <signal name="ItemsPropertiesUpdated"><arg type="a(ia{sv})"/><arg type="a(ias)"/></signal>
    <signal name="LayoutUpdated"><arg type="u"/><arg type="i"/></signal>
    <signal name="ItemActivationRequested"><arg type="i"/><arg type="u"/></signal>
  </interface>
</node>
"""

MENU_OPEN, MENU_PAUSE, MENU_LOCK, MENU_QUIT = 1, 3, 4, 6


class Tray:
    def __init__(self, on_activate, on_pause, on_lock, on_quit, on_availability=None):
        self.cb = {
            MENU_OPEN: on_activate,
            MENU_PAUSE: on_pause,
            MENU_LOCK: on_lock,
            MENU_QUIT: on_quit,
        }
        self.on_activate = on_activate
        self.on_availability = on_availability
        self.available = False
        self.down = self.up = 0
        self.paused = self.locked = False
        self.revision = 1
        self.conn = None
        self._name_owned = False
        self._watcher_present = False
        self.bus_name = f"org.kde.StatusNotifierItem-{os.getpid()}-1"
        try:
            self.conn = Gio.bus_get_sync(Gio.BusType.SESSION, None)
            sni = Gio.DBusNodeInfo.new_for_xml(SNI_XML).interfaces[0]
            menu = Gio.DBusNodeInfo.new_for_xml(MENU_XML).interfaces[0]
            self.conn.register_object(SNI_PATH, sni, self._sni_call, self._sni_get, None)
            self.conn.register_object(MENU_PATH, menu, self._menu_call, self._menu_get, None)
            Gio.bus_own_name_on_connection(
                self.conn, self.bus_name, Gio.BusNameOwnerFlags.NONE,
                self._name_acquired, None,
            )
            Gio.bus_watch_name_on_connection(
                self.conn, WATCHER_NAME, Gio.BusNameWatcherFlags.NONE,
                self._watcher_appeared, self._watcher_vanished,
            )
        except Exception:
            self.conn = None

    def _name_acquired(self, *_):
        self._name_owned = True
        self._try_register()

    def _watcher_appeared(self, *_):
        self._watcher_present = True
        self._try_register()

    def _watcher_vanished(self, *_):
        self._watcher_present = False
        self._set_available(False)

    def _try_register(self):
        if not self.conn:
            return
        try:
            self.conn.call(
                WATCHER_NAME, WATCHER_PATH, WATCHER_NAME, "RegisterStatusNotifierItem",
                GLib.Variant("(s)", (self.bus_name,)), None,
                Gio.DBusCallFlags.NONE, 5000, None, self._register_done,
            )
        except Exception:
            pass

    def _register_done(self, conn, res):
        try:
            conn.call_finish(res)
            self._set_available(True)
        except Exception:
            self._set_available(False)

    def _set_available(self, value):
        if value != self.available:
            self.available = value
            if self.on_availability:
                self.on_availability(value)

    def _icon(self):
        if self.locked:
            return "network-offline-symbolic"
        if self.paused:
            return "media-playback-pause-symbolic"
        return "network-workgroup-symbolic"

    def _tooltip_text(self):
        text = f"↓ {format_rate(self.down)}   ↑ {format_rate(self.up)}"
        if self.locked:
            text += "\nNetwork Locked"
        elif self.paused:
            text += "\nRules Paused"
        return text

    def update(self, down, up, paused, locked):
        if self.conn is None:
            return
        changed = (paused, locked) != (self.paused, self.locked)
        self.down, self.up, self.paused, self.locked = down, up, paused, locked
        if changed:
            self.revision += 1
            self._emit(MENU_PATH, MENU_IFACE, "LayoutUpdated", GLib.Variant("(ui)", (self.revision, 0)))
            self._emit(SNI_PATH, SNI_IFACE, "NewIcon", None)
        self._emit(SNI_PATH, SNI_IFACE, "NewToolTip", None)

    def _emit(self, path, iface, signal, params):
        try:
            if self.conn:
                self.conn.emit_signal(None, path, iface, signal, params)
        except Exception:
            pass

    def _sni_get(self, _conn, _sender, _path, _iface, prop):
        icon = self._icon()
        empty_pixmap = GLib.Variant("a(iiay)", [])
        values = {
            "Category": GLib.Variant("s", "ApplicationStatus"),
            "Id": GLib.Variant("s", "netlimiter"),
            "Title": GLib.Variant("s", "NetLimiter-Linux"),
            "Status": GLib.Variant("s", "Active"),
            "WindowId": GLib.Variant("u", 0),
            "IconName": GLib.Variant("s", icon),
            "IconPixmap": empty_pixmap,
            "OverlayIconName": GLib.Variant("s", ""),
            "OverlayIconPixmap": empty_pixmap,
            "AttentionIconName": GLib.Variant("s", ""),
            "AttentionIconPixmap": empty_pixmap,
            "AttentionMovieName": GLib.Variant("s", ""),
            "ToolTip": GLib.Variant("(sa(iiay)ss)", (icon, [], "NetLimiter-Linux", self._tooltip_text())),
            "ItemIsMenu": GLib.Variant("b", False),
            "Menu": GLib.Variant("o", MENU_PATH),
        }
        return values.get(prop)

    def _sni_call(self, _conn, _sender, _path, _iface, method, _params, invocation):
        if method in ("Activate", "SecondaryActivate"):
            self.on_activate()
        invocation.return_value(None)

    def _items(self):
        return [
            (MENU_OPEN, {"label": "Open NetLimiter-Linux"}),
            (2, {"type": "separator"}),
            (MENU_PAUSE, {"label": "Pause Rules", "toggle-type": "checkmark",
                          "toggle-state": 1 if self.paused else 0}),
            (MENU_LOCK, {"label": "Network Locked", "toggle-type": "checkmark",
                         "toggle-state": 1 if self.locked else 0}),
            (5, {"type": "separator"}),
            (MENU_QUIT, {"label": "Quit"}),
        ]

    @staticmethod
    def _props(props):
        out = {}
        for key, value in props.items():
            out[key] = GLib.Variant("i" if key == "toggle-state" else "s", value)
        return out

    def _layout(self):
        children = [
            GLib.Variant("(ia{sv}av)", (item_id, self._props(props), []))
            for item_id, props in self._items()
        ]
        root = (0, {"children-display": GLib.Variant("s", "submenu")}, children)
        return GLib.Variant("(u(ia{sv}av))", (self.revision, root))

    def _menu_get(self, _conn, _sender, _path, _iface, prop):
        return {
            "Version": GLib.Variant("u", 3),
            "TextDirection": GLib.Variant("s", "ltr"),
            "Status": GLib.Variant("s", "normal"),
            "IconThemePath": GLib.Variant("as", []),
        }.get(prop)

    def _clicked(self, item_id):
        cb = self.cb.get(item_id)
        if cb:
            cb()

    def _menu_call(self, _conn, _sender, _path, _iface, method, params, invocation):
        if method == "GetLayout":
            invocation.return_value(self._layout())
        elif method == "GetGroupProperties":
            ids = set(params.unpack()[0])
            rows = [(i, self._props(p)) for i, p in self._items() if not ids or i in ids]
            invocation.return_value(GLib.Variant("(a(ia{sv}))", (rows,)))
        elif method == "GetProperty":
            item_id, name = params.unpack()
            props = dict(self._items()).get(item_id, {})
            if name in props:
                invocation.return_value(GLib.Variant("(v)", (self._props(props)[name],)))
            else:
                invocation.return_error_literal(
                    Gio.dbus_error_quark(), Gio.DBusError.INVALID_ARGS, "unknown property")
        elif method == "Event":
            item_id, event_id, _data, _ts = params.unpack()
            if event_id == "clicked":
                self._clicked(item_id)
            invocation.return_value(None)
        elif method == "EventGroup":
            for item_id, event_id, _data, _ts in params.unpack()[0]:
                if event_id == "clicked":
                    self._clicked(item_id)
            invocation.return_value(GLib.Variant("(ai)", ([],)))
        elif method == "AboutToShow":
            invocation.return_value(GLib.Variant("(b)", (True,)))
        elif method == "AboutToShowGroup":
            invocation.return_value(GLib.Variant("(aiai)", ([], [])))
        else:
            invocation.return_value(None)


# ---------------------------------------------------------------- Helpers
def format_rate(bps: float) -> str:
    bps = int(bps)
    if bps < 1024:
        return f"{bps} B/s"
    if bps < 1024 * 1024:
        return f"{bps / 1024:.1f} KB/s"
    return f"{bps / (1024 * 1024):.2f} MB/s"


def format_bytes(n: int) -> str:
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return "0 B"


def client_request(payload: dict) -> dict:
    last_err = "socket missing"
    for path in SOCKET_CANDIDATES:
        if not os.path.exists(path):
            continue
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(1.5)
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
    raise RuntimeError(last_err)


class AppItem(GObject.Object):
    exe = GObject.Property(type=str, default="")
    name = GObject.Property(type=str, default="")
    down = GObject.Property(type=GObject.TYPE_INT64, default=0)
    up = GObject.Property(type=GObject.TYPE_INT64, default=0)
    conns = GObject.Property(type=int, default=0)
    down_total = GObject.Property(type=GObject.TYPE_INT64, default=0)
    up_total = GObject.Property(type=GObject.TYPE_INT64, default=0)
    down_limit = GObject.Property(type=int, default=0)
    up_limit = GObject.Property(type=int, default=0)
    rule_kind = GObject.Property(type=str, default="")

    down_txt = GObject.Property(type=str, default="")
    up_txt = GObject.Property(type=str, default="")
    down_total_txt = GObject.Property(type=str, default="")
    up_total_txt = GObject.Property(type=str, default="")
    down_limit_txt = GObject.Property(type=str, default="—")
    up_limit_txt = GObject.Property(type=str, default="—")
    rule_symbol = GObject.Property(type=str, default="●")
    rule_css = GObject.Property(type=str, default="rule-dot-none")
    conns_txt = GObject.Property(type=str, default="0")
    gicon = GObject.Property(type=Gio.Icon)

    def fill(self, proc: dict, rule: dict | None):
        self.props.name = proc.get("name") or "unknown"
        self.props.down = int(proc.get("down_bps", 0))
        self.props.up = int(proc.get("up_bps", 0))
        self.props.conns = int(proc.get("connections", 0))
        self.props.down_total = int(proc.get("down_total", 0))
        self.props.up_total = int(proc.get("up_total", 0))
        self.props.down_txt = format_rate(self.down)
        self.props.up_txt = format_rate(self.up)
        self.props.down_total_txt = format_bytes(self.down_total)
        self.props.up_total_txt = format_bytes(self.up_total)
        self.props.conns_txt = str(self.conns)

        kind, dl, ul = "", 0, 0
        if rule and rule.get("enabled"):
            action = rule.get("action")
            if action == "block":
                kind = "block"
            elif action == "limit":
                kind = "limit"
                dl = int(rule.get("down_kbps") or 0)
                ul = int(rule.get("up_kbps") or 0)
            elif action == "allow":
                kind = "allow"

        self.props.rule_kind = kind
        self.props.down_limit = dl
        self.props.up_limit = ul
        self.props.down_limit_txt = f"{dl}k" if dl else "—"
        self.props.up_limit_txt = f"{ul}k" if ul else "—"

        if kind == "block":
            self.props.rule_symbol = "●"
            self.props.rule_css = "rule-dot-blocked"
        elif kind == "limit":
            self.props.rule_symbol = "●"
            self.props.rule_css = "rule-dot-limited"
        elif kind == "allow":
            self.props.rule_symbol = "●"
            self.props.rule_css = "rule-dot-allowed"
        else:
            self.props.rule_symbol = "●"
            self.props.rule_css = "rule-dot-none"


class ConnItem(GObject.Object):
    remote = GObject.Property(type=str, default="")
    local = GObject.Property(type=str, default="")
    proto = GObject.Property(type=str, default="")
    state = GObject.Property(type=str, default="")
    down_txt = GObject.Property(type=str, default="")
    up_txt = GObject.Property(type=str, default="")


class NetLimiterWindow(Adw.ApplicationWindow):
    def __init__(self, app):
        super().__init__(application=app, title="NetLimiter-Linux")
        self.set_default_size(1200, 720)

        self.style_manager = Adw.StyleManager.get_default()
        self.style_manager.set_color_scheme(Adw.ColorScheme.FORCE_DARK)

        self.snapshot = None
        self.items: dict[str, AppItem] = {}
        self.app_icons = self._load_icons()
        self._busy = False
        self._last_selected = None
        self._autostart_tried = False
        self._starting = False
        self.paused = False
        self.locked = False
        self._preselect_exe = getattr(app, "preselect_exe", None)
        self._preselect_tries = 0
        self.connect("close-request", self._on_close_request)

        self._build_actions()
        self._build_ui()
        self._tick()
        GLib.timeout_add(1000, self._tick)

    def _load_icons(self):
        mapping = {}
        for info in Gio.AppInfo.get_all():
            try:
                executable = info.get_executable()
                icon = info.get_icon()
                if executable and icon:
                    base_exe = os.path.basename(executable).lower()
                    mapping[base_exe] = icon
                    app_id = info.get_id()
                    if app_id:
                        mapping[app_id.lower().split(".")[0]] = icon
            except Exception:
                continue
        return mapping

    def _build_actions(self):
        for name, cb in (
            ("clear", self.on_clear),
            ("privacy", self.on_privacy),
            ("about", self.on_about),
        ):
            act = Gio.SimpleAction.new(name, None)
            act.connect("activate", cb)
            self.add_action(act)

    def _build_ui(self):
        s = STRINGS
        view = Adw.ToolbarView()
        self.toast = Adw.ToastOverlay()
        self.toast.set_child(view)
        self.set_content(self.toast)

        header = Adw.HeaderBar()
        self.win_title = Adw.WindowTitle(title=s["title"], subtitle=s["subtitle"])
        header.set_title_widget(self.win_title)

        self.lock_btn = Gtk.ToggleButton(label=s["lock_off"], icon_name="changes-prevent-symbolic")
        self.lock_btn.add_css_class("destructive-action")
        self.lock_btn.connect("toggled", self.on_lock)
        header.pack_start(self.lock_btn)

        pause_box = Gtk.Box(spacing=8)
        pause_box.set_valign(Gtk.Align.CENTER)

        self.pause_label = Gtk.Label(label=s["running"])
        self.pause_label.add_css_class("nl-pause-on")

        self.pause_switch = Gtk.Switch()
        self.pause_switch.set_active(False)
        self.pause_switch.set_valign(Gtk.Align.CENTER)
        self.pause_switch.connect("state-set", self.on_pause_switch)

        pause_box.append(self.pause_label)
        pause_box.append(self.pause_switch)
        header.pack_start(pause_box)

        self.theme_btn = Gtk.Button(icon_name="weather-clear-night-symbolic", valign=Gtk.Align.CENTER)
        self.theme_btn.set_tooltip_text("Toggle Dark / Light Theme")
        self.theme_btn.connect("clicked", self.on_toggle_theme)
        header.pack_end(self.theme_btn)

        menu = Gio.Menu()
        menu.append(s["clear_rules"], "win.clear")
        menu.append(s["autostart"], "win.autostart_toggle")
        menu.append(s["privacy"], "win.privacy")
        menu.append(s["about"], "win.about")

        autostart_act = Gio.SimpleAction.new_stateful(
            "autostart_toggle", None, GLib.Variant.new_boolean(self.is_autostart_enabled())
        )
        autostart_act.connect("change-state", self.on_toggle_autostart)
        self.add_action(autostart_act)

        header.pack_end(Gtk.MenuButton(icon_name="open-menu-symbolic", menu_model=menu))
        view.add_top_bar(header)

        self.banner = Adw.Banner(title=s["service_offline"])
        self.banner.connect("button-clicked", self._start_daemon)
        view.add_top_bar(self.banner)

        tools = Gtk.Box(spacing=8)
        tools.add_css_class("nl-toolbar")

        self.search = Gtk.SearchEntry(placeholder_text=s["search"], hexpand=True)
        self.search.connect(
            "search-changed", lambda *_: self.filter.changed(Gtk.FilterChange.DIFFERENT)
        )
        tools.append(self.search)

        self.active_only = Gtk.ToggleButton(label=s["active_only"])
        self.active_only.connect(
            "toggled", lambda *_: self.filter.changed(Gtk.FilterChange.DIFFERENT)
        )
        tools.append(self.active_only)

        tools.append(Gtk.Separator(orientation=Gtk.Orientation.VERTICAL))

        self.block_btn = Gtk.ToggleButton(label=s["block"], icon_name="action-unavailable-symbolic")
        self.block_btn.add_css_class("destructive-action")
        self.block_btn.connect("toggled", self.on_block)
        tools.append(self.block_btn)

        self.allow_btn = Gtk.ToggleButton(label=s["allow"], icon_name="object-select-symbolic")
        self.allow_btn.add_css_class("suggested-action")
        self.allow_btn.connect("toggled", self.on_allow_rule)
        tools.append(self.allow_btn)

        self.limit_pop = self._build_limit_popover()
        self.limit_btn = Gtk.MenuButton(
            label=s["limit"], icon_name="speedometer-symbolic", popover=self.limit_pop
        )
        self.limit_btn.add_css_class("suggested-action")
        tools.append(self.limit_btn)

        self.reset_btn = Gtk.Button(label=s["remove_rule"], icon_name="edit-delete-symbolic")
        self.reset_btn.connect("clicked", self.on_reset)
        tools.append(self.reset_btn)
        view.add_top_bar(tools)

        self.paned = Gtk.Paned(
            orientation=Gtk.Orientation.HORIZONTAL,
            hexpand=True,
            vexpand=True,
            position=800,
        )
        self.paned.set_start_child(self._build_apps_table())
        self.paned.set_end_child(self._build_connections_panel())
        self.paned.set_shrink_start_child(False)
        self.paned.set_shrink_end_child(True)
        view.set_content(self.paned)

        self.status = Gtk.Label(xalign=0)
        self.status.add_css_class("nl-status")
        self.status.add_css_class("dim-label")
        view.add_bottom_bar(self.status)

        css = Gtk.CssProvider()
        css.load_from_data(CSS)
        Gtk.StyleContext.add_provider_for_display(
            Gdk.Display.get_default(), css, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
        )
        self._update_buttons()

    def get_autostart_path(self):
        autostart_dir = Path.home() / ".config" / "autostart"
        autostart_dir.mkdir(parents=True, exist_ok=True)
        return autostart_dir / "com.netlimiter.linux.desktop"

    def is_autostart_enabled(self):
        return self.get_autostart_path().exists()

    def on_toggle_autostart(self, action, value):
        state = value.get_boolean()
        action.set_state(value)
        desktop_file_path = self.get_autostart_path()

        desktop_file_path.parent.mkdir(parents=True, exist_ok=True)

        if state:
            script_path = os.path.abspath(__file__)
            desktop_content = f"""[Desktop Entry]
Type=Application
Name=NetLimiter-Linux
Exec=python3 {script_path} --background
Hidden=false
NoDisplay=false
X-GNOME-Autostart-enabled=true
"""
            desktop_file_path.write_text(desktop_content)
            self.toast.add_toast(Adw.Toast(title="Autostart enabled & file created"))
        else:
            if desktop_file_path.exists():
                desktop_file_path.unlink()
            self.toast.add_toast(Adw.Toast(title="Autostart disabled"))

    def on_toggle_theme(self, _btn):
        if self.style_manager.get_dark():
            self.style_manager.set_color_scheme(Adw.ColorScheme.FORCE_LIGHT)
            self.theme_btn.set_icon_name("weather-clear-symbolic")
        else:
            self.style_manager.set_color_scheme(Adw.ColorScheme.FORCE_DARK)
            self.theme_btn.set_icon_name("weather-clear-night-symbolic")

    def _build_limit_popover(self):
        s = STRINGS
        pop = Gtk.Popover()
        grid = Gtk.Grid(
            column_spacing=10,
            row_spacing=8,
            margin_start=14,
            margin_end=14,
            margin_top=14,
            margin_bottom=14,
        )
        self.down_spin = Gtk.SpinButton.new_with_range(0, 1_000_000, 50)
        self.up_spin = Gtk.SpinButton.new_with_range(0, 1_000_000, 50)

        self.lbl_down_spin = Gtk.Label(label=s["down_kb"], xalign=0)
        self.lbl_up_spin = Gtk.Label(label=s["up_kb"], xalign=0)
        self.lbl_zero_hint = Gtk.Label(label=s["zero_hint"], xalign=0)
        self.lbl_zero_hint.add_css_class("dim-label")

        grid.attach(self.lbl_down_spin, 0, 0, 1, 1)
        grid.attach(self.down_spin, 1, 0, 1, 1)
        grid.attach(self.lbl_up_spin, 0, 1, 1, 1)
        grid.attach(self.up_spin, 1, 1, 1, 1)
        grid.attach(self.lbl_zero_hint, 0, 2, 2, 1)

        self.apply_btn = Gtk.Button(label=s["apply"])
        self.apply_btn.add_css_class("suggested-action")
        self.apply_btn.connect("clicked", self.on_apply_limit)
        grid.attach(self.apply_btn, 0, 3, 2, 1)
        pop.set_child(grid)
        return pop

    def _text_col(self, title, prop, sort_key, css=None, width=0, align=1.0):
        factory = Gtk.SignalListItemFactory()

        def setup(_f, li):
            lbl = Gtk.Label(xalign=align)
            lbl.add_css_class("nl-stat")
            if css:
                lbl.add_css_class(css)
            li.set_child(lbl)

        def bind(_f, li):
            li._b = li.get_item().bind_property(
                prop, li.get_child(), "label", GObject.BindingFlags.SYNC_CREATE
            )

        def unbind(_f, li):
            b = getattr(li, "_b", None)
            if b:
                b.unbind()
                li._b = None

        factory.connect("setup", setup)
        factory.connect("bind", bind)
        factory.connect("unbind", unbind)
        col = Gtk.ColumnViewColumn(title=title, factory=factory)
        if width:
            col.set_fixed_width(width)
        col.set_resizable(True)
        col.set_sorter(
            Gtk.CustomSorter.new(
                lambda a, b, _d: (sort_key(a) > sort_key(b)) - (sort_key(a) < sort_key(b)), None
            )
        )
        return col

    def _name_col(self):
        factory = Gtk.SignalListItemFactory()

        def setup(_f, li):
            box = Gtk.Box(spacing=8)
            img = Gtk.Image(pixel_size=18)
            lbl = Gtk.Label(xalign=0, hexpand=True, ellipsize=Pango.EllipsizeMode.END)
            box.append(img)
            box.append(lbl)
            li.set_child(box)

        def bind(_f, li):
            item = li.get_item()
            box = li.get_child()
            img, lbl = box.get_first_child(), box.get_last_child()

            if item.exe == "":
                img.set_from_icon_name("network-workgroup-symbolic")
            else:
                exe_base = os.path.basename(item.exe).lower()
                icon = self.app_icons.get(exe_base)
                if not icon:
                    for k, v in self.app_icons.items():
                        if k in exe_base or exe_base in k:
                            icon = v
                            break
                if icon:
                    img.set_from_gicon(icon)
                else:
                    img.set_from_icon_name("application-x-executable")

            li._b = item.bind_property(
                "name", lbl, "label", GObject.BindingFlags.SYNC_CREATE
            )

        def unbind(_f, li):
            b = getattr(li, "_b", None)
            if b:
                b.unbind()
                li._b = None

        factory.connect("setup", setup)
        factory.connect("bind", bind)
        factory.connect("unbind", unbind)
        col = Gtk.ColumnViewColumn(title=STRINGS["app_name"], factory=factory)
        col.set_expand(True)
        col.set_resizable(True)
        col.set_sorter(
            Gtk.CustomSorter.new(
                lambda a, b, _d: (a.name.lower() > b.name.lower())
                - (a.name.lower() < b.name.lower()),
                None,
            )
        )
        return col

    def _rule_col(self):
        factory = Gtk.SignalListItemFactory()

        def setup(_f, li):
            lbl = Gtk.Label(xalign=0.5)
            li.set_child(lbl)

        def bind(_f, li):
            item = li.get_item()
            lbl = li.get_child()

            def upd(*_):
                lbl.set_text(item.rule_symbol)
                lbl.remove_css_class("rule-dot-blocked")
                lbl.remove_css_class("rule-dot-limited")
                lbl.remove_css_class("rule-dot-allowed")
                lbl.remove_css_class("rule-dot-none")
                lbl.add_css_class(item.rule_css)

            li._b1 = item.bind_property("rule-symbol", lbl, "label", GObject.BindingFlags.SYNC_CREATE)
            li._hid = item.connect("notify::rule-css", upd)
            upd()

        def unbind(_f, li):
            b1 = getattr(li, "_b1", None)
            if b1:
                b1.unbind()
                li._b1 = None
            hid = getattr(li, "_hid", None)
            if hid:
                li.get_item().disconnect(hid)
                li._hid = None

        factory.connect("setup", setup)
        factory.connect("bind", bind)
        factory.connect("unbind", unbind)

        col = Gtk.ColumnViewColumn(title=STRINGS["rule"], factory=factory)
        col.set_fixed_width(45)
        col.set_resizable(True)
        col.set_sorter(
            Gtk.CustomSorter.new(
                lambda a, b, _d: (a.rule_kind > b.rule_kind) - (a.rule_kind < b.rule_kind), None
            )
        )
        return col

    def _build_apps_table(self):
        s = STRINGS
        self.store = Gio.ListStore.new(AppItem)

        self.global_item = AppItem(exe="", name="🌐 Global Control (System-wide)")
        self.store.append(self.global_item)

        def match(item):
            if item.exe == "":
                return True
            q = self.search.get_text().strip().lower()
            if q and q not in f"{item.name} {item.exe}".lower():
                return False
            if self.active_only.get_active() and item.down + item.up == 0:
                return False
            return True

        self.filter = Gtk.CustomFilter.new(match)
        filtered = Gtk.FilterListModel(model=self.store, filter=self.filter)
        self.apps_view = Gtk.ColumnView(show_row_separators=True, show_column_separators=True)
        self.apps_view.add_css_class("nl-table")
        sorted_model = Gtk.SortListModel(model=filtered, sorter=self.apps_view.get_sorter())
        self.selection = Gtk.SingleSelection(
            model=sorted_model, autoselect=False, can_unselect=True
        )
        self.selection.connect("notify::selected-item", self.on_select)
        self.apps_view.set_model(self.selection)

        self.context_popover = self._build_context_menu()
        gesture = Gtk.GestureClick.new()
        gesture.set_button(3)
        gesture.connect("released", self.on_right_click)
        self.apps_view.add_controller(gesture)

        self.col_name = self._name_col()
        self.col_down = self._text_col(s["down"], "down_txt", lambda i: i.down, "nl-down", 75)
        self.col_up = self._text_col(s["up"], "up_txt", lambda i: i.up, "nl-up", 75)
        self.col_dlimit = self._text_col(s["down_limit"], "down_limit_txt", lambda i: i.down_limit, None, 55)
        self.col_ulimit = self._text_col(s["up_limit"], "up_limit_txt", lambda i: i.up_limit, None, 55)
        self.col_rule = self._rule_col()
        self.col_conns = self._text_col(s["conns"], "conns_txt", lambda i: i.conns, None, 45)
        self.col_dtotal = self._text_col(s["total_down"], "down_total_txt", lambda i: i.down_total, None, 70)
        self.col_utotal = self._text_col(s["total_up"], "up_total_txt", lambda i: i.up_total, None, 70)

        for c in (
            self.col_name,
            self.col_down,
            self.col_up,
            self.col_dlimit,
            self.col_ulimit,
            self.col_rule,
            self.col_conns,
            self.col_dtotal,
            self.col_utotal,
        ):
            self.apps_view.append_column(c)

        scroll = Gtk.ScrolledWindow(vexpand=True, hexpand=True)
        scroll.set_child(self.apps_view)
        return scroll

    def _build_context_menu(self):
        pop = Gtk.Popover()
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4, margin_start=6, margin_end=6, margin_top=6, margin_bottom=6)

        btn_block = Gtk.Button()
        btn_block.set_child(Gtk.Label(label="🚫 Block", xalign=0))
        btn_block.add_css_class("flat")
        btn_block.connect("clicked", lambda *_: (self.context_popover.popdown(), self._ctx_action("block")))

        btn_allow = Gtk.Button()
        btn_allow.set_child(Gtk.Label(label="✅ Allow", xalign=0))
        btn_allow.add_css_class("flat")
        btn_allow.connect("clicked", lambda *_: (self.context_popover.popdown(), self._ctx_action("allow")))

        btn_limit = Gtk.Button()
        btn_limit.set_child(Gtk.Label(label="⚡ Limit...", xalign=0))
        btn_limit.add_css_class("flat")
        btn_limit.connect("clicked", lambda *_: (self.context_popover.popdown(), self.limit_pop.popup()))

        btn_web = Gtk.Button()
        btn_web.set_child(Gtk.Label(label="🌐 Search App Online", xalign=0))
        btn_web.add_css_class("flat")
        btn_web.connect("clicked", lambda *_: (self.context_popover.popdown(), self._ctx_action("search_web")))

        btn_remove = Gtk.Button()
        btn_remove.set_child(Gtk.Label(label="🗑 Remove Rule", xalign=0))
        btn_remove.add_css_class("flat")
        btn_remove.connect("clicked", lambda *_: (self.context_popover.popdown(), self.on_reset(None)))

        box.append(btn_block)
        box.append(btn_allow)
        box.append(btn_limit)
        box.append(Gtk.Separator(orientation=Gtk.Orientation.HORIZONTAL))
        box.append(btn_web)
        box.append(Gtk.Separator(orientation=Gtk.Orientation.HORIZONTAL))
        box.append(btn_remove)

        pop.set_child(box)
        pop.set_parent(self.apps_view)
        return pop

    def on_right_click(self, gesture, n_press, x, y):
        sel = self.selection.get_selected_item()
        if not sel:
            return
        rect = Gdk.Rectangle()
        rect.x, rect.y, rect.width, rect.height = int(x), int(y), 1, 1
        self.context_popover.set_pointing_to(rect)
        self.context_popover.popup()

    def _ctx_action(self, action_type):
        sel = self.selection.get_selected_item()
        if not sel:
            return
        target_exe = sel.exe if sel.exe != "" else "global"
        if action_type == "block":
            self._send({"cmd": "set_rule", "exe": target_exe, "action": "block", "enabled": True}, "Blocked")
        elif action_type == "allow":
            self._send({"cmd": "set_rule", "exe": target_exe, "action": "allow", "enabled": True}, "Allowed")
        elif action_type == "search_web":
            query = sel.name if sel.exe != "" else "Linux Network System"
            url = f"https://duckduckgo.com/?q={query.replace(' ', '+')}"
            Gio.AppInfo.launch_default_for_uri(url, None)

    def _build_connections_panel(self):
        s = STRINGS
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, vexpand=True, hexpand=True)
        box.add_css_class("sidebar-frame")

        header_box = Gtk.Box(spacing=6, margin_start=10, margin_end=10, margin_top=8, margin_bottom=8)
        self.ip_title_lbl = Gtk.Label(label=s["ip_panel_title"], xalign=0, hexpand=True)
        self.ip_title_lbl.add_css_class("heading")

        self.show_all_conns = Gtk.ToggleButton(label=s["show_listen"], valign=Gtk.Align.CENTER)
        self.show_all_conns.connect("toggled", self.on_toggle_all_conns)

        header_box.append(self.ip_title_lbl)
        header_box.append(self.show_all_conns)
        box.append(header_box)

        self.conn_store = Gio.ListStore.new(ConnItem)
        self.conn_view = Gtk.ColumnView(show_row_separators=True, show_column_separators=True)
        self.conn_view.add_css_class("nl-table")
        self.conn_view.set_model(Gtk.NoSelection(model=self.conn_store))

        self.conn_popover = self._build_conn_context_menu()
        conn_gesture = Gtk.GestureClick.new()
        conn_gesture.set_button(3)
        conn_gesture.connect("released", self.on_conn_right_click)
        self.conn_view.add_controller(conn_gesture)

        self.col_ip_dest = self._text_col(s["dest_ip"], "remote", True, None, 0, 0.0)
        self.col_ip_proto = self._text_col(s["proto"], "proto", False, None, 50, 0.5)
        self.col_ip_state = self._text_col(s["state"], "state", False, None, 55, 0.5)
        self.col_ip_down = self._text_col(s["down"], "down_txt", False, "nl-down", 65, 0.5)
        self.col_ip_up = self._text_col(s["up"], "up_txt", False, "nl-up", 65, 0.5)

        self.col_ip_dest.set_expand(True)

        for c in (
            self.col_ip_dest,
            self.col_ip_proto,
            self.col_ip_state,
            self.col_ip_down,
            self.col_ip_up,
        ):
            self.conn_view.append_column(c)

        cscroll = Gtk.ScrolledWindow(vexpand=True, hexpand=True)
        cscroll.set_child(self.conn_view)
        box.append(cscroll)
        return box

    def _build_conn_context_menu(self):
        pop = Gtk.Popover()
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4, margin_start=6, margin_end=6, margin_top=6, margin_bottom=6)

        btn_lookup = Gtk.Button()
        btn_lookup.set_child(Gtk.Label(label="🔍 Look up IP Source", xalign=0))
        btn_lookup.add_css_class("flat")
        btn_lookup.connect("clicked", lambda *_: (self.conn_popover.popdown(), self._lookup_selected_ip()))

        box.append(btn_lookup)
        pop.set_child(box)
        pop.set_parent(self.conn_view)
        return pop

    def on_conn_right_click(self, gesture, n_press, x, y):
        rect = Gdk.Rectangle()
        rect.x, rect.y, rect.width, rect.height = int(x), int(y), 1, 1
        self.conn_popover.set_pointing_to(rect)
        self.conn_popover.popup()

    def _lookup_selected_ip(self):
        sel_app = self.selection.get_selected_item()
        if not sel_app or sel_app.exe == "":
            return

        for c in (self.snapshot or {}).get("connections", []):
            if c.get("exe") == sel_app.exe:
                remote = str(c.get("remote", ""))
                if remote and remote != "None":
                    ip = remote.rsplit(":", 1)[0].strip("[]")
                    if ip and ip not in ("0.0.0.0", "::", "127.0.0.1"):
                        url = f"https://ipinfo.io/{ip}"
                        Gio.AppInfo.launch_default_for_uri(url, None)
                        return

    def _tick(self):
        if not self._busy:
            self._busy = True
            threading.Thread(target=self._fetch, daemon=True).start()
        return True

    def _fetch(self):
        resp, err, offline = None, None, False
        try:
            resp = client_request({"cmd": "snapshot"})
            if not resp.get("ok") or not resp.get("snapshot"):
                err = resp.get("error") or "no snapshot"
        except Exception as exc:
            err, offline = str(exc), True
        GLib.idle_add(self._apply, resp, err, offline)

    def _apply(self, resp, err, offline=False):
        s = STRINGS
        self._busy = False
        if err:
            if offline:
                if not self._starting:
                    self.banner.set_title(f"{s['service_offline']} ({err})")
                self.banner.set_button_label(s["start_service"])
                if not self._autostart_tried:
                    self._autostart_tried = True
                    self._start_daemon()
            else:
                self.banner.set_title(err)
                self.banner.set_button_label(None)
            self.banner.set_revealed(True)
            return False
        self.banner.set_revealed(False)
        snap = resp["snapshot"]
        self.snapshot = snap

        iface_down = int(snap.get("iface_down_bps", 0))
        iface_up = int(snap.get("iface_up_bps", 0))
        rules_list = snap.get("rules", [])
        global_rule = next(
            (r for r in rules_list if not r.get("exe") or r.get("exe") == "global"), None
        )

        global_proc = {
            "name": "🌐 Global Control (System-wide)",
            "down_bps": iface_down,
            "up_bps": iface_up,
            "connections": sum(int(p.get("connections", 0)) for p in snap.get("processes", [])),
            "down_total": sum(int(p.get("down_total", 0)) for p in snap.get("processes", [])),
            "up_total": sum(int(p.get("up_total", 0)) for p in snap.get("processes", [])),
        }
        self.global_item.fill(global_proc, global_rule)

        paused = bool(snap.get("paused"))
        self.paused = paused
        is_locked = bool(snap.get("lock_all"))
        self.locked = is_locked

        tray = getattr(self.get_application(), "tray", None)
        if tray:
            tray.update(iface_down, iface_up, paused, is_locked)

        parts = [
            f"↓ {format_rate(iface_down)}",
            f"↑ {format_rate(iface_up)}",
            s["root"] if snap.get("privileged") else s["no_root"],
            "nft OK" if snap.get("nft_ok") else "nft N/A",
            f"⏸ {s['paused']}" if paused else f"▶ {s['running']}",
            f"{len(snap.get('processes', []))} Apps",
        ]
        self.status.set_text("   ·   ".join(f"⁨{p}⁩" for p in parts))

        self.lock_btn.handler_block_by_func(self.on_lock)
        self.lock_btn.set_active(is_locked)
        self.lock_btn.set_label(s["lock_on"] if is_locked else s["lock_off"])
        self.lock_btn.handler_unblock_by_func(self.on_lock)

        self.pause_switch.handler_block_by_func(self.on_pause_switch)
        self.pause_switch.set_active(paused)
        self.pause_switch.handler_unblock_by_func(self.on_pause_switch)

        self.pause_label.remove_css_class("nl-pause-on")
        self.pause_label.remove_css_class("nl-pause-off")
        if paused:
            self.pause_label.set_text(s["paused"])
            self.pause_label.add_css_class("nl-pause-off")
        else:
            self.pause_label.set_text(s["running"])
            self.pause_label.add_css_class("nl-pause-on")

        rules = {r.get("exe"): r for r in rules_list}
        seen = set()
        for proc in snap.get("processes", []):
            exe = proc.get("exe") or "unknown"
            seen.add(exe)
            item = self.items.get(exe)
            if item is None:
                item = AppItem(exe=exe)
                self.items[exe] = item
                self.store.append(item)
            item.fill(proc, rules.get(exe))

        self.filter.changed(Gtk.FilterChange.DIFFERENT)
        self.apps_view.get_sorter().changed(Gtk.SorterChange.DIFFERENT)

        self._try_preselect()

        sel = self.selection.get_selected_item()
        if sel and sel.exe != "":
            self._fill_connections(sel)
        else:
            self.conn_store.remove_all()

        self._update_buttons()
        return False

    def _try_preselect(self):
        exe = self._preselect_exe
        if not exe:
            return
        filtered = self.selection.get_model()
        for j in range(filtered.get_n_items()):
            item = filtered.get_item(j)
            if item is not None and item.exe == exe:
                self._preselect_exe = None
                self.selection.set_selected(j)
                GLib.timeout_add(300, lambda: self.limit_pop.popup() or False)
                return
        self._preselect_tries += 1
        if self._preselect_tries > 10:
            self._preselect_exe = None

    def request_select(self, exe):
        self._preselect_exe = exe
        self._preselect_tries = 0
        self._try_preselect()

    def toggle_pause(self):
        self._send({"cmd": "set_paused", "enabled": not self.paused})

    def toggle_lock(self):
        self._send({"cmd": "set_lock", "enabled": not self.locked})

    def _on_close_request(self, *_):
        app = self.get_application()
        if getattr(app, "quitting", False):
            return False
        self.set_visible(False)
        return True

    def _start_daemon(self, *_):
        if self._starting:
            return
        self._starting = True
        self.banner.set_title("Starting service...")

        def work():
            try:
                r = subprocess.run(
                    ["systemctl", "start", "netlimiter-daemon.service"],
                    capture_output=True,
                    text=True,
                    timeout=120,
                )
                msg = None if r.returncode == 0 else (r.stderr.strip() or "Failed to start service")
            except Exception as exc:
                msg = str(exc)
            GLib.idle_add(self._after_start, msg)

        threading.Thread(target=work, daemon=True).start()

    def _after_start(self, msg):
        self._starting = False
        if msg:
            self.toast.add_toast(Adw.Toast(title=msg))
        self._tick()
        return False

    def _fill_connections(self, sel):
        rows = []
        show_all = self.show_all_conns.get_active()
        for c in (self.snapshot or {}).get("connections", []):
            if c.get("exe") != sel.exe:
                continue
            if not show_all and self._is_noise(c):
                continue
            rows.append(
                ConnItem(
                    remote=str(c.get("remote", "")),
                    local=str(c.get("local", "")),
                    proto=str(c.get("proto", "")).upper(),
                    state=str(c.get("state", "")),
                    down_txt=format_rate(c.get("down_bps", 0)),
                    up_txt=format_rate(c.get("up_bps", 0)),
                )
            )
        self.conn_store.splice(0, self.conn_store.get_n_items(), rows)

    @staticmethod
    def _is_noise(c: dict) -> bool:
        if c.get("state") == "LISTEN":
            return True
        host = str(c.get("remote", "")).rsplit(":", 1)[0].strip("[]")
        return host in ("0.0.0.0", "::") or host.startswith("127.") or host == "::1"

    def on_toggle_all_conns(self, *_):
        sel = self.selection.get_selected_item()
        if sel and sel.exe != "":
            self._fill_connections(sel)

    def on_select(self, *_):
        sel = self.selection.get_selected_item()
        key = sel.exe if sel else None
        if key != self._last_selected:
            self._last_selected = key
            if sel:
                self.down_spin.set_value(sel.down_limit)
                self.up_spin.set_value(sel.up_limit)
                if sel.exe != "":
                    self._fill_connections(sel)
                else:
                    self.conn_store.remove_all()
            else:
                self.conn_store.remove_all()
        self._update_buttons()

    def _update_buttons(self):
        sel = self.selection.get_selected_item()
        has = sel is not None
        self.block_btn.set_sensitive(has)
        self.allow_btn.set_sensitive(has)
        self.limit_btn.set_sensitive(has)
        self.reset_btn.set_sensitive(has and bool(sel.rule_kind))

        self.block_btn.handler_block_by_func(self.on_block)
        self.block_btn.set_active(bool(has and sel.rule_kind == "block"))
        self.block_btn.handler_unblock_by_func(self.on_block)

        self.allow_btn.handler_block_by_func(self.on_allow_rule)
        self.allow_btn.set_active(bool(has and sel.rule_kind == "allow"))
        self.allow_btn.handler_unblock_by_func(self.on_allow_rule)

    def _send(self, payload, ok_msg=None):
        def work():
            try:
                client_request(payload)
                msg = ok_msg
            except Exception as exc:
                msg = str(exc)
            GLib.idle_add(self._after_cmd, msg)

        threading.Thread(target=work, daemon=True).start()

    def _after_cmd(self, msg):
        if msg:
            self.toast.add_toast(Adw.Toast(title=msg))
        self._tick()
        return False

    def on_lock(self, btn):
        active = btn.get_active()
        btn.set_label(STRINGS["lock_on"] if active else STRINGS["lock_off"])
        self._send({"cmd": "set_lock", "enabled": active})

    def on_pause_switch(self, _switch, state):
        if bool(state) == bool(self.paused):
            return False
        msg = "⏸ Paused" if state else "▶ Resumed"
        self._send({"cmd": "set_paused", "enabled": bool(state)}, msg)
        return False

    def on_block(self, btn):
        sel = self.selection.get_selected_item()
        if not sel:
            return
        target_exe = sel.exe if sel.exe != "" else "global"
        if btn.get_active():
            self._send({"cmd": "set_rule", "exe": target_exe, "action": "block", "enabled": True})
        else:
            self._send({"cmd": "delete_rule", "exe": target_exe})

    def on_allow_rule(self, btn):
        sel = self.selection.get_selected_item()
        if not sel:
            return
        target_exe = sel.exe if sel.exe != "" else "global"
        if btn.get_active():
            self._send({"cmd": "set_rule", "exe": target_exe, "action": "allow", "enabled": True}, "Allowed rule applied")
        else:
            self._send({"cmd": "delete_rule", "exe": target_exe}, "Rule removed")

    def on_apply_limit(self, _btn):
        sel = self.selection.get_selected_item()
        if not sel:
            return
        down, up = int(self.down_spin.get_value()), int(self.up_spin.get_value())
        self.limit_pop.popdown()
        target_exe = sel.exe if sel.exe != "" else "global"

        if not down and not up:
            self._send({"cmd": "delete_rule", "exe": target_exe}, "Limit removed")
            return
        self._send(
            {
                "cmd": "set_rule",
                "exe": target_exe,
                "action": "limit",
                "down_kbps": down or None,
                "up_kbps": up or None,
                "enabled": True,
            },
            "Limit applied",
        )

    def on_reset(self, _btn):
        sel = self.selection.get_selected_item()
        if sel:
            self.down_spin.set_value(0)
            self.up_spin.set_value(0)
            target_exe = sel.exe if sel.exe != "" else "global"
            self._send({"cmd": "delete_rule", "exe": target_exe}, "Rule removed")

    def on_clear(self, *_):
        self._send({"cmd": "clear_rules"}, "All rules cleared")

    def on_privacy(self, *_):
        s = STRINGS
        dialog = Adw.MessageDialog(
            transient_for=self,
            heading=s["privacy_title"],
            body=s["privacy_text"]
        )
        dialog.add_response("ok", "OK")
        dialog.set_response_appearance("ok", Adw.ResponseAppearance.SUGGESTED)
        dialog.connect("response", lambda d, _: d.destroy())
        dialog.present()

    def on_about(self, *_):
        cls = getattr(Adw, "AboutDialog", None)
        if cls:
            d = cls(
                application_name="NetLimiter-Linux",
                version="0.7.7",
                comments="Network traffic monitor & rate limiter for Linux.",
                developer_name="WiiPro38 (NOVAFroge)",
                copyright="© WiiPro38 (NOVAFroge). All rights Reserved.",
            )
            d.present(self)
        else:
            Adw.AboutWindow(
                transient_for=self,
                application_name="NetLimiter-Linux",
                version="0.7.7",
                comments="Network traffic monitor & rate limiter for Linux.",
                developer_name="WiiPro38 (NOVAFroge)",
                copyright="© WiiPro38 (NOVAFroge). All rights Reserved.",
            ).present()


class NetLimiterApp(Adw.Application):
    def __init__(self, *args, **kwargs):
        super().__init__(
            application_id="com.netlimiter.linux",
            flags=Gio.ApplicationFlags.HANDLES_COMMAND_LINE,
            *args, **kwargs
        )
        self.preselect_exe = None
        self.win = None
        self.tray = None
        self.quitting = False
        self._tray_held = False
        self.add_main_option(
            "select", ord("s"), GLib.OptionFlags.NONE,
            GLib.OptionArg.STRING, "Select app path", "PATH",
        )
        self.add_main_option(
            "background", ord("b"), GLib.OptionFlags.NONE,
            GLib.OptionArg.NONE, "Start hidden in the system tray", None,
        )

    def do_startup(self):
        Adw.Application.do_startup(self)
        self.tray = Tray(
            on_activate=self.toggle_window,
            on_pause=lambda: self.win and self.win.toggle_pause(),
            on_lock=lambda: self.win and self.win.toggle_lock(),
            on_quit=self.quit_app,
            on_availability=self._tray_availability,
        )
        self.hold()
        self._tray_held = True

    def _tray_availability(self, available):
        if not self._tray_held:
            self.hold()
            self._tray_held = True

    def _ensure_window(self):
        if self.win is None:
            self.win = NetLimiterWindow(self)
        return self.win

    def toggle_window(self):
        win = self._ensure_window()
        if win.is_visible() and win.is_active():
            win.set_visible(False)
        else:
            win.present()

    def quit_app(self, *_):
        self.quitting = True
        if self._tray_held:
            self.release()
            self._tray_held = False
        self.quit()

    def do_command_line(self, command_line):
        options = command_line.get_options_dict()
        select = None
        if options.contains("select"):
            variant = options.lookup_value("select", GLib.VariantType.new("s"))
            if variant is not None:
                select = variant.get_string()
        background = options.contains("background")

        first = self.win is None
        self.preselect_exe = select if first else None
        win = self._ensure_window()
        if select and not first:
            win.request_select(select)

        if not (background and first and not select):
            win.present()
        return 0

    def do_activate(self):
        self._ensure_window().present()


def main():
    app = NetLimiterApp()
    sys.exit(app.run(sys.argv))


if __name__ == "__main__":
    main()
