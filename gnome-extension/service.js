// Tracks and controls the wayland-agent daemon's systemd user unit
// (wayland-agent.service, installed by install.sh) over the systemd
// user manager's D-Bus API.  Only Gio/GLib/GObject — no gnome-shell
// imports — so it can be exercised from plain `gjs -m`.
//
// `state` is one of:
//   'missing'      unit file not installed (or systemd unreachable)
//   'off'          inactive
//   'failed'       last run failed (e.g. consent declined)
//   'starting'     activating — the daemon is waiting on the portal
//                  consent dialog (it only reports READY once accepted)
//   'on'           active
//   'stopping'     deactivating

import GLib from 'gi://GLib';
import Gio from 'gi://Gio';
import GObject from 'gi://GObject';

export const UNIT = 'wayland-agent.service';

const SYSTEMD = 'org.freedesktop.systemd1';
const MANAGER_PATH = '/org/freedesktop/systemd1';
const MANAGER_IFACE = 'org.freedesktop.systemd1.Manager';
const UNIT_IFACE = 'org.freedesktop.systemd1.Unit';
const PROPS_IFACE = 'org.freedesktop.DBus.Properties';

Gio._promisify(Gio.DBusConnection.prototype, 'call');

const ACTIVE_STATES = {
    active: 'on',
    reloading: 'on',
    activating: 'starting',
    deactivating: 'stopping',
    inactive: 'off',
    failed: 'failed',
};

export const AgentService = GObject.registerClass({
    Properties: {
        'state': GObject.ParamSpec.string('state', null, null,
            GObject.ParamFlags.READABLE, 'missing'),
    },
}, class AgentService extends GObject.Object {
    constructor(unit = UNIT) {
        super();
        this._unit = unit;
        this._state = 'missing';
        this._bus = Gio.DBus.session;
        this._unitPath = null;
        this._subs = [];
        this._cancellable = new Gio.Cancellable();

        // Unit-file installs/removals arrive as a manager reload.
        this._subs.push(this._bus.signal_subscribe(SYSTEMD, MANAGER_IFACE,
            'Reloading', MANAGER_PATH, null, Gio.DBusSignalFlags.NONE,
            () => this._refresh()));
        this._subs.push(this._bus.signal_subscribe(SYSTEMD, MANAGER_IFACE,
            'UnitFilesChanged', MANAGER_PATH, null, Gio.DBusSignalFlags.NONE,
            () => this._refresh()));

        this._setup().catch(e => this._fail('setup', e));
    }

    get state() {
        return this._state;
    }

    get active() {
        return this._state === 'on' || this._state === 'starting';
    }

    async start() {
        await this._managerCall('StartUnit', new GLib.Variant('(ss)', [this._unit, 'replace']));
    }

    async stop() {
        await this._managerCall('StopUnit', new GLib.Variant('(ss)', [this._unit, 'replace']));
    }

    destroy() {
        this._cancellable.cancel();
        for (const id of this._subs) this._bus.signal_unsubscribe(id);
        this._subs = [];
    }

    async _setup() {
        // The user manager only emits PropertiesChanged for clients that
        // have subscribed.  Deliberately never Unsubscribe: the flag is
        // per bus connection, and gnome-shell's connection is shared.
        await this._managerCall('Subscribe', null);

        // A unit's object path is derived from its name and is stable
        // even while systemd has it unloaded, so subscribe by path once.
        const [path] = (await this._managerCall('LoadUnit',
            new GLib.Variant('(s)', [this._unit]))).deepUnpack();
        this._unitPath = path;
        this._subs.push(this._bus.signal_subscribe(SYSTEMD, PROPS_IFACE,
            'PropertiesChanged', path, UNIT_IFACE, Gio.DBusSignalFlags.NONE,
            () => this._refresh()));
        await this._refresh();
    }

    async _refresh() {
        if (!this._unitPath) return;
        try {
            const reply = await this._bus.call(SYSTEMD, this._unitPath, PROPS_IFACE,
                'GetAll', new GLib.Variant('(s)', [UNIT_IFACE]),
                new GLib.VariantType('(a{sv})'), Gio.DBusCallFlags.NONE, -1,
                this._cancellable);
            // Unpack only the two strings: recursiveUnpack() would also
            // convert the unit's u64 timestamps/limits and warn about
            // precision loss on every refresh.
            const [props] = reply.deepUnpack();
            const loadState = props.LoadState?.unpack();
            const activeState = props.ActiveState?.unpack();
            if (loadState === 'not-found')
                this._setState('missing');
            else
                this._setState(ACTIVE_STATES[activeState] ?? 'off');
        } catch (e) {
            this._fail('refresh', e);
        }
    }

    _managerCall(method, params) {
        return this._bus.call(SYSTEMD, MANAGER_PATH, MANAGER_IFACE, method,
            params, null, Gio.DBusCallFlags.NONE, -1, this._cancellable);
    }

    _fail(what, e) {
        if (e.matches?.(Gio.IOErrorEnum, Gio.IOErrorEnum.CANCELLED)) return;
        console.warn(`wayland-agent: ${what} of ${this._unit} failed: ${e.message}`);
        this._setState('missing');
    }

    _setState(state) {
        if (state === this._state) return;
        this._state = state;
        this.notify('state');
    }
});
