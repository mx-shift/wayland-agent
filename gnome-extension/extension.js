// wayland-agent gnome-shell extension.
//
// Hosts a D-Bus interface (com.mxshift.WaylandAgent) inside gnome-shell
// so unprivileged callers — specifically the wayland-agent daemon — can
// enumerate windows, focus them, and read monitor geometry.  GNOME's
// own org.gnome.Shell.Introspect API does the same thing but gates
// access by hardcoded caller whitelist (orca + a few others); regular
// apps see AccessDenied.  An in-shell extension sidesteps that because
// it runs in the gjs sandbox alongside Mutter and inherits the same
// privilege.
//
// Methods (see schemas/dbus.xml-equivalent IFACE_XML below):
//
//   GetWindows()              -> aa{sv}
//     One dict per visible top-level Meta.Window.  Fields are the
//     metadata the wayland-agent daemon needs to do click targeting,
//     stream-to-window mapping, focus control: id, title, wm_class,
//     app_id, pid, monitor index, frame_rect (with deco) + buffer_rect
//     (client area), focused/minimized/maximized/fullscreen booleans,
//     is_x11 flag (XWayland clients identify themselves here so the
//     daemon knows whether app_id will be set).
//
//   GetWindow(t id)           -> a{sv}
//     Same dict for a single window.  Errors if id isn't currently
//     mapped.
//
//   FocusWindow(t id)         -> ()
//     Activates the window — gives it keyboard focus and raises it.
//     Useful right before chaining keyboard injection through the
//     RemoteDesktop portal.
//
//   GetMonitors()             -> aa{sv}
//     One dict per Meta logical monitor: index, connector name (when
//     resolvable, e.g. "DP-1"), x/y/width/height in global coords,
//     scale, is_primary.
//
// Signals:
//
//   WindowOpened(t id)
//   WindowClosed(t id)
//   WindowFocusChanged(t id)
//
// All ids are Meta.Window.get_id() — a stable uint64 valid for the
// window's lifetime.

import GLib from 'gi://GLib';
import Gio from 'gi://Gio';
import Meta from 'gi://Meta';
import {Extension} from 'resource:///org/gnome/shell/extensions/extension.js';

const BUS_NAME = 'com.mxshift.WaylandAgent';
const OBJECT_PATH = '/com/mxshift/WaylandAgent';

const IFACE_XML = `
<node>
  <interface name="com.mxshift.WaylandAgent">
    <method name="GetWindows">
      <arg type="aa{sv}" direction="out" name="windows"/>
    </method>
    <method name="GetWindow">
      <arg type="t" direction="in" name="id"/>
      <arg type="a{sv}" direction="out" name="window"/>
    </method>
    <method name="FocusWindow">
      <arg type="t" direction="in" name="id"/>
    </method>
    <method name="GetMonitors">
      <arg type="aa{sv}" direction="out" name="monitors"/>
    </method>
    <signal name="WindowOpened">
      <arg type="t" name="id"/>
    </signal>
    <signal name="WindowClosed">
      <arg type="t" name="id"/>
    </signal>
    <signal name="WindowFocusChanged">
      <arg type="t" name="id"/>
    </signal>
  </interface>
</node>`;

/* ---------- Window dict builder ---------- */

// Returns a plain object whose values are GLib.Variant — Gjs's
// DBusExportedObject marshalls this into a{sv} automatically.
function windowToDict(win) {
    const fr = win.get_frame_rect();
    const br = win.get_buffer_rect();

    // Best-effort app id resolution.  GTK / portal-aware apps report
    // gtk_application_id; Flatpak'd apps report sandboxed_app_id.
    // X11 apps generally have neither and rely on wm_class.
    let appId = '';
    try { appId = win.get_gtk_application_id() || ''; } catch (_) { /* no-op */ }
    if (!appId) {
        try { appId = win.get_sandboxed_app_id() || ''; } catch (_) { /* no-op */ }
    }

    const isX11 = (win.get_client_type() === Meta.WindowClientType.X11);

    let maximized = false;
    try { maximized = win.get_maximized() !== 0; } catch (_) { /* no-op */ }

    return {
        id:          GLib.Variant.new_uint64(win.get_id()),
        title:       GLib.Variant.new_string(win.get_title() || ''),
        wm_class:    GLib.Variant.new_string(win.get_wm_class() || ''),
        app_id:      GLib.Variant.new_string(appId),
        pid:         GLib.Variant.new_int32(win.get_pid()),
        monitor:     GLib.Variant.new_int32(win.get_monitor()),
        is_x11:      GLib.Variant.new_boolean(isX11),
        frame_x:     GLib.Variant.new_int32(fr.x),
        frame_y:     GLib.Variant.new_int32(fr.y),
        frame_w:     GLib.Variant.new_int32(fr.width),
        frame_h:     GLib.Variant.new_int32(fr.height),
        client_x:    GLib.Variant.new_int32(br.x),
        client_y:    GLib.Variant.new_int32(br.y),
        client_w:    GLib.Variant.new_int32(br.width),
        client_h:    GLib.Variant.new_int32(br.height),
        focused:     GLib.Variant.new_boolean(win.has_focus()),
        minimized:   GLib.Variant.new_boolean(win.minimized),
        maximized:   GLib.Variant.new_boolean(maximized),
        fullscreen:  GLib.Variant.new_boolean(win.is_fullscreen()),
        on_all_workspaces: GLib.Variant.new_boolean(win.is_on_all_workspaces()),
    };
}

/* ---------- Monitor dict builder ---------- */

function monitorToDict(idx) {
    const display = global.display;
    const rect = display.get_monitor_geometry(idx);
    let scale = 1.0;
    try { scale = display.get_monitor_scale(idx); } catch (_) { /* no-op */ }
    const primary = (idx === display.get_primary_monitor());

    // Resolving the connector name (e.g. "DP-1") goes through the
    // monitor manager which has shifted between GNOME releases.  Try a
    // couple of known method names; if none work, leave name empty —
    // callers can still match by index or geometry.
    let name = '';
    try {
        const mm = (Meta.MonitorManager && Meta.MonitorManager.get) ? Meta.MonitorManager.get() : null;
        if (mm) {
            if (typeof mm.get_monitor_connector === 'function') {
                name = mm.get_monitor_connector(idx) || '';
            } else if (typeof mm.get_monitor_for_connector === 'function') {
                // Inverse direction; iterate is too expensive — skip.
            }
        }
    } catch (_) { /* no-op */ }

    return {
        index:      GLib.Variant.new_int32(idx),
        name:       GLib.Variant.new_string(name),
        x:          GLib.Variant.new_int32(rect.x),
        y:          GLib.Variant.new_int32(rect.y),
        width:      GLib.Variant.new_int32(rect.width),
        height:     GLib.Variant.new_int32(rect.height),
        scale:      GLib.Variant.new_double(scale),
        is_primary: GLib.Variant.new_boolean(primary),
    };
}

/* ---------- Helpers ---------- */

function allWindows() {
    return global.get_window_actors()
        .map(a => a.get_meta_window())
        .filter(w => w !== null);
}

function findWindowById(id) {
    // Meta IDs are uint64; gjs receives them as BigInt over D-Bus.
    // get_id() returns a plain Number unless the value exceeds 2^53;
    // compare as BigInt to be safe.
    const target = BigInt(id);
    for (const w of allWindows()) {
        if (BigInt(w.get_id()) === target) return w;
    }
    return null;
}

/* ---------- Extension class ---------- */

export default class WaylandAgentExtension extends Extension {
    enable() {
        this._dbus = Gio.DBusExportedObject.wrapJSObject(IFACE_XML, this);
        this._dbus.export(Gio.DBus.session, OBJECT_PATH);

        this._ownerId = Gio.bus_own_name(
            Gio.BusType.SESSION,
            BUS_NAME,
            Gio.BusNameOwnerFlags.NONE,
            null,    // bus acquired
            null,    // name acquired
            () => {  // name lost
                console.warn(`wayland-agent: lost bus name ${BUS_NAME}`);
            }
        );

        // window-created fires for every new top-level — wire per-window
        // 'unmanaged' to emit WindowClosed once each window's lifetime
        // ends.  Keep window-created handler so signals stay live across
        // app launches.
        this._sigCreated = global.display.connect('window-created', (_d, win) => {
            const id = win.get_id();
            this._emit('WindowOpened', new GLib.Variant('(t)', [id]));
            const unmanaged = win.connect('unmanaged', () => {
                this._emit('WindowClosed', new GLib.Variant('(t)', [id]));
                win.disconnect(unmanaged);
            });
        });
        this._sigFocus = global.display.connect('notify::focus-window', () => {
            const fw = global.display.focus_window;
            this._emit('WindowFocusChanged',
                new GLib.Variant('(t)', [fw ? fw.get_id() : 0]));
        });
    }

    disable() {
        if (this._sigCreated) global.display.disconnect(this._sigCreated);
        if (this._sigFocus) global.display.disconnect(this._sigFocus);
        this._sigCreated = null;
        this._sigFocus = null;

        if (this._ownerId) Gio.bus_unown_name(this._ownerId);
        this._ownerId = 0;

        if (this._dbus) {
            this._dbus.unexport();
            this._dbus = null;
        }
    }

    _emit(name, params) {
        if (this._dbus) {
            this._dbus.emit_signal(name, params);
        }
    }

    /* ---------- D-Bus methods ---------- */

    GetWindows() {
        return allWindows().map(windowToDict);
    }

    GetWindow(id) {
        const w = findWindowById(id);
        if (!w) {
            throw new GLib.Error(Gio.IOErrorEnum, Gio.IOErrorEnum.NOT_FOUND,
                `no window with id ${id}`);
        }
        return windowToDict(w);
    }

    FocusWindow(id) {
        const w = findWindowById(id);
        if (!w) {
            throw new GLib.Error(Gio.IOErrorEnum, Gio.IOErrorEnum.NOT_FOUND,
                `no window with id ${id}`);
        }
        w.activate(global.get_current_time());
    }

    GetMonitors() {
        const n = global.display.get_n_monitors();
        const out = [];
        for (let i = 0; i < n; i++) out.push(monitorToDict(i));
        return out;
    }
}
