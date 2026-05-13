#!/usr/bin/env bash
# Install + enable the wayland-agent gnome-shell extension.
#
# Drops metadata.json + extension.js into the per-user extension
# directory, then asks gnome-extensions to enable the UUID.  On a
# Wayland session enabling a new extension requires gnome-shell to
# reload — log out and back in.  (On X11 you can do Alt+F2 'r' Enter,
# but Wayland forbids hot-reload, no way around it.)

set -eu

UUID="wayland-agent@mxshift.com"
SRC="$(cd "$(dirname "$0")" && pwd)"
DEST="${HOME}/.local/share/gnome-shell/extensions/${UUID}"

if [[ ! -f "$SRC/metadata.json" || ! -f "$SRC/extension.js" ]]; then
    echo "ERROR: install.sh expects to live next to metadata.json + extension.js" >&2
    exit 2
fi

mkdir -p "$DEST"
cp -f "$SRC/metadata.json" "$DEST/"
cp -f "$SRC/extension.js"  "$DEST/"
echo "Installed extension files into $DEST"

if command -v gnome-extensions >/dev/null 2>&1; then
    if gnome-extensions enable "$UUID" 2>/dev/null; then
        echo "Enabled $UUID"
    else
        echo "WARNING: gnome-extensions enable failed — try again after gnome-shell reload." >&2
    fi
else
    echo "WARNING: gnome-extensions CLI not found; enable manually via 'Extensions' app." >&2
fi

cat >&2 <<EOF

NOTE: GNOME on Wayland will not pick up the new extension until
gnome-shell reloads.  Log out and back in (or reboot) — then verify
with:
    gnome-extensions show $UUID | grep State
    gdbus call --session --dest com.mxshift.WaylandAgent \\
        --object-path /com/mxshift/WaylandAgent \\
        --method com.mxshift.WaylandAgent.GetMonitors

If GetMonitors returns a list, the extension is live and the
wayland-agent daemon's extension-backed subcommands will work.
EOF
