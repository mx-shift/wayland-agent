//! Daemon mode for wayland-agent.
//!
//! Architecture:
//! - `wayland-agent daemon` establishes one RemoteDesktop + Screencast
//!   portal session, opens a PipeWire fd, then listens on a unix socket
//!   for line-delimited JSON commands.
//! - All other subcommands (`key`, `type`, `click`, `screenshot`, ...)
//!   are thin clients that connect to the socket and send one request.
//!
//! Why a daemon: the portal session and PipeWire connection are
//! expensive to set up (consent dialog on first session, plus several
//! round-trips on every restore). The persistent-token "restore"
//! flow in ashpd doesn't actually bring back screencast streams on
//! GNOME 49, so a per-invocation client would re-prompt for monitor
//! selection every time. Keeping one process alive sidesteps all of
//! that — the user consents once, then every CLI invocation is
//! near-instant socket IO.
//!
//! Lifecycle:
//! - User runs `wayland-agent daemon` (foreground) or under a
//!   systemd-user service. First start surfaces the portal consent
//!   dialog; subsequent commands reuse the session.
//! - On daemon exit (reboot, ^C), the next start needs a new
//!   consent. No on-disk persistence — simpler and avoids the
//!   broken restore_token path.

use std::collections::HashMap;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use ashpd::desktop::{
    PersistMode,
    Session,
    remote_desktop::{
        DeviceType, KeyState, NotifyKeyboardKeycodeOptions, NotifyKeyboardKeysymOptions,
        NotifyPointerButtonOptions, NotifyPointerMotionAbsoluteOptions,
        RemoteDesktop, SelectDevicesOptions, StartOptions,
    },
    screencast::{
        CursorMode, OpenPipeWireRemoteOptions, Screencast, SelectSourcesOptions, SourceType,
    },
};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;

/// Where the daemon listens. Prefer XDG_RUNTIME_DIR (cleaned on
/// logout / shared with other user-scoped services); fall back to
/// HOME-rooted cache.
pub fn socket_path() -> Result<PathBuf> {
    if let Some(rt) = std::env::var_os("XDG_RUNTIME_DIR") {
        return Ok(PathBuf::from(rt).join("wayland-agent.sock"));
    }
    let home = std::env::var_os("HOME").ok_or_else(|| anyhow!("no HOME"))?;
    Ok(PathBuf::from(home).join(".cache/wayland-agent.sock"))
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "cmd")]
pub enum Request {
    /// Press+release a single keysym by name (Space, Return, a, ...).
    Key { name: String },
    /// Press a chord of keysyms separated by '+'.  All pressed in
    /// left-to-right order, released in reverse order (modifier-held
    /// semantics).  Example: "F12+o" for the DOSBox-X swap hotkey.
    KeyChord { keys: String },
    /// Press+release a Linux evdev keycode directly.
    KeyCode { code: i32 },
    /// Press (and hold) a single keysym; pair with KeyUp to release.
    KeyDown { name: String },
    /// Release a keysym previously held via KeyDown.
    KeyUp { name: String },
    /// Type a UTF-8 string by mapping each char to its keysym.  `delay`
    /// is milliseconds to wait after each character; None = as fast as possible.
    Type { text: String, delay: Option<u64> },
    /// Absolute pointer move on the given stream.  `x`/`y` are in
    /// screenshot-pixel space of that stream (what you read off the
    /// PNG) — they map 1:1 to the portal's pointer coordinates.
    Move { x: f64, y: f64, stream: usize },
    /// Press+release a pointer button at the current position.
    Click { button: String },
    ButtonDown { button: String },
    ButtonUp { button: String },
    /// Move + press + release, in screenshot-pixel space of `stream`.
    ClickAt { x: f64, y: f64, button: String, stream: usize },
    /// Absolute pointer move in **global logical** coords (the space
    /// the extension reports window/monitor rects in).  The daemon
    /// resolves which stream covers the point, subtracts its origin, and
    /// scales the offset up to the stream's physical frame space (what
    /// the portal expects).
    MoveGlobal { x: f64, y: f64 },
    /// Move (global logical coords) + press + release.
    ClickAtGlobal { x: f64, y: f64, button: String },
    /// Capture one frame per stream. Writes PNGs to the supplied
    /// path (suffixed when there are multiple streams).
    Screenshot { out: PathBuf },
    /// Cheap liveness check — daemon returns Ok immediately.
    Ping,
    /// Number of streams + per-stream rect info (portal-only).
    Streams,
    /// Return the stream index whose portal-reported rect covers the
    /// given screen point (portal-only).
    StreamAt { x: f64, y: f64 },
    /* ------------- Extension-required requests ------------- */
    /// List visible top-level windows (com.mxshift.WaylandAgent.GetWindows).
    Windows,
    /// Get one window's metadata by id.
    Window { id: u64 },
    /// Activate (focus + raise) a window by id.
    FocusWindow { id: u64 },
    /// List monitors with geometry + scale.
    Monitors,
    /// Find the window whose wm_class/app_id/title matches `pattern`
    /// (case-insensitive substring).  Exactly one match prints its full
    /// metadata; several matches is an error listing the candidates
    /// unless `all` is set, which prints every match.
    FindWindow {
        pattern: String,
        #[serde(default)]
        all: bool,
    },
    /// Focus a window, move to coordinates relative to its origin, and
    /// click — the one-shot "drive this window" primitive.  `window` is
    /// a numeric id or a find-window pattern that must match exactly
    /// one window.  `x`/`y` are global-logical units measured from the
    /// window's frame origin (or client origin when `client` is set).
    ClickWindow {
        window: String,
        x: f64,
        y: f64,
        button: String,
        #[serde(default)]
        client: bool,
    },
    /// Focus a window, then type a UTF-8 string into it — same window
    /// resolution and focus-wait as ClickWindow, same typing semantics
    /// (incl. per-char `delay` pacing) as Type.
    TypeWindow {
        window: String,
        text: String,
        #[serde(default)]
        delay: Option<u64>,
    },
    /// Dump a window's AT-SPI accessibility tree: role, name, and rect
    /// per element.  `depth` limits recursion; `all` includes elements
    /// not currently SHOWING (popped-down menus etc.).
    UiTree {
        window: String,
        #[serde(default)]
        depth: Option<u32>,
        #[serde(default)]
        all: bool,
    },
    /// Search a window's AT-SPI tree for elements whose name contains
    /// `pattern` (case-insensitive; empty matches everything), optionally
    /// restricted to a role.  Prints each match with a center point for
    /// `click-in`.
    UiFind {
        window: String,
        pattern: String,
        #[serde(default)]
        role: Option<String>,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "ok")]
pub enum Response {
    #[serde(rename = "true")]
    Ok { detail: Option<String>, paths: Option<Vec<PathBuf>> },
    #[serde(rename = "false")]
    Err { error: String },
}

impl Response {
    fn ok() -> Self { Response::Ok { detail: None, paths: None } }
    fn ok_paths(paths: Vec<PathBuf>) -> Self {
        Response::Ok { detail: None, paths: Some(paths) }
    }
    fn ok_detail(detail: String) -> Self {
        Response::Ok { detail: Some(detail), paths: None }
    }
    fn err(error: impl Into<String>) -> Self {
        Response::Err { error: error.into() }
    }
}

/// Per-stream info kept after portal Start.  position+size come from
/// the screencast portal's Stream metadata when the source is a
/// monitor (they describe the monitor's rect in global screen coords);
/// for Window sources the portal omits them and they stay None.
///
/// Coordinate spaces — the whole reason clicks used to miss:
/// - `position`/`size` are **logical** global coords (mutter's layout,
///   the same space the gnome-shell extension reports window rects in).
/// - `frame_size` is the **physical** pixel size of the PipeWire frame
///   we actually capture (learned on the first `screenshot`).  On a
///   HiDPI/fractional monitor it is `size * monitor_scale`, so a
///   screenshot PNG is bigger than the logical `size`.
/// - The RemoteDesktop portal's `NotifyPointerMotionAbsolute` wants
///   coordinates in the stream's **physical** frame space — the same
///   pixels a screenshot is in.  Mutter divides the incoming (x, y) by
///   the monitor scale itself to reach global logical coords
///   (`screen = logical_monitor.origin + stream_xy / scale`), so the
///   caller must NOT pre-scale.
///
/// Consequences for the two coordinate entry points:
/// - A pixel read off a screenshot is already in physical frame space,
///   so it maps to a portal coordinate **1:1** — no conversion, scaled
///   monitor or not (see `screenshot_to_input`).
/// - A global *logical* coordinate (from the extension) must be scaled
///   **up** by `frame_size / size` (physical / logical) after the
///   stream origin is subtracted, because the portal wants physical
///   pixels (see `logical_local_to_frame`).
///
/// An earlier version scaled screenshot pixels *down* by `size /
/// frame_size` before handing them to the portal; mutter then divided
/// by the scale a second time, so every click landed at
/// `target / scale`.  On an unscaled (1.0) monitor `size == frame_size`
/// so the bug was invisible — which is why it only showed up on HiDPI.
///
/// Caveat (mutter fractional-scaling quirk): although the transform is
/// physical, mutter validates the incoming coordinate against the
/// monitor's *logical* rect, so it only accepts `0..size` and rejects
/// anything in the `size..frame_size` margin with "Invalid position".
/// On a scaled monitor that leaves the right/bottom of a
/// physical-resolution screenshot unreachable by the pointer.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StreamInfo {
    pub node_id: u32,
    pub position: Option<(i32, i32)>,
    pub size: Option<(i32, i32)>,
    /// Physical size of the captured PipeWire frame, learned lazily on
    /// the first `screenshot`.  None until then (falls back to a 1:1
    /// ratio, which is correct on unscaled monitors).
    pub frame_size: Option<(u32, u32)>,
}

impl StreamInfo {
    /// Convert a screenshot-pixel coordinate (physical frame space, what
    /// a caller reads off the PNG) into the pointer coordinate the
    /// RemoteDesktop portal expects.  The portal wants physical
    /// frame-space coordinates and applies the monitor scale itself, so
    /// this is the identity — a screenshot pixel already IS a valid
    /// portal coordinate, on scaled and unscaled monitors alike.
    pub fn screenshot_to_input(&self, x: f64, y: f64) -> (f64, f64) {
        (x, y)
    }

    /// Convert a stream-local *logical* coordinate (a global logical
    /// point with this stream's origin already subtracted) into the
    /// physical frame-space coordinate the portal expects.  Scales up by
    /// `frame_size / size` (physical / logical); 1:1 when `frame_size`
    /// is unknown — correct for unscaled monitors, and the only case
    /// where a click before the startup frame-size probe could be off on
    /// a scaled monitor (take a screenshot first to prime the ratio).
    pub fn logical_local_to_frame(&self, lx: f64, ly: f64) -> (f64, f64) {
        match (self.size, self.frame_size) {
            (Some((lw, lh)), Some((fw, fh))) if lw > 0 && lh > 0 => {
                (lx * fw as f64 / lw as f64, ly * fh as f64 / lh as f64)
            }
            _ => (lx, ly),
        }
    }

    /// Verify a final portal coordinate (physical frame space, what
    /// `NotifyPointerMotionAbsolute` receives) lands in the range mutter
    /// will accept.  Per the type doc, mutter validates incoming
    /// remote-desktop coordinates against the monitor's *logical* rect
    /// even though it treats them as physical, so anything at or beyond
    /// `size` is rejected with a bare "Invalid position".  Catch that
    /// here and explain the fractional-scaling limitation instead.
    ///
    /// No-op when the portal didn't report `size` (Window-source
    /// streams): there's no rect to bound against, so let the portal
    /// decide.
    fn check_reachable(&self, ix: f64, iy: f64) -> Result<()> {
        let Some((lw, lh)) = self.size else { return Ok(()) };
        let (lwf, lhf) = (lw as f64, lh as f64);
        if ix < 0.0 || iy < 0.0 || ix >= lwf || iy >= lhf {
            let frame = self
                .frame_size
                .map(|(w, h)| format!("{w}x{h}"))
                .unwrap_or_else(|| "?".into());
            return Err(anyhow!(
                "point ({ix:.0}, {iy:.0}) is outside this monitor's reachable \
                 pointer range 0..{lw} x 0..{lh}. GNOME/mutter validates \
                 remote-desktop coordinates against the monitor's LOGICAL size, \
                 so on a fractional/HiDPI monitor the right/bottom margin of a \
                 physical-resolution screenshot ({frame}) can't be clicked."
            ));
        }
        Ok(())
    }
}

impl StreamInfo {
    /// Does this stream's reported rect cover point (x, y) in global
    /// screen coordinates?  Returns false if the portal didn't supply
    /// position+size for this stream (Window-source streams).
    pub fn contains(&self, x: f64, y: f64) -> bool {
        match (self.position, self.size) {
            (Some((sx, sy)), Some((sw, sh))) => {
                let xi = x as i32;
                let yi = y as i32;
                xi >= sx && xi < sx + sw && yi >= sy && yi < sy + sh
            }
            _ => false,
        }
    }
}

/// Resolve a global logical coordinate to (node_id, frame_x, frame_y).
/// Finds the stream whose logical rect covers (x, y), subtracts its
/// origin, then scales the logical-local offset up to physical
/// frame-space — the space the portal's `NotifyPointerMotionAbsolute`
/// expects.  This is the path for coordinates that come from the
/// gnome-shell extension (`windows`/`find-window`/`monitors`), which
/// are logical, not from a screenshot.
fn resolve_global(streams: &[StreamInfo], x: f64, y: f64) -> Result<(u32, f64, f64)> {
    let s = streams
        .iter()
        .find(|s| s.contains(x, y))
        .ok_or_else(|| anyhow!("no stream covers global point ({x}, {y})"))?;
    let (px, py) = s.position.ok_or_else(|| anyhow!("stream has no position"))?;
    let (fx, fy) = s.logical_local_to_frame(x - px as f64, y - py as f64);
    s.check_reachable(fx, fy)?;
    Ok((s.node_id, fx, fy))
}

/// Shared state held across socket connections. Wrapped in a Mutex so
/// we serialize portal calls — ashpd futures are !Send across
/// awaits in some cases, and we don't want to interleave
/// pointer/key events anyway (one client at a time keeps semantics
/// predictable).
struct DaemonState {
    rd: RemoteDesktop,
    sc: Screencast,
    /// Shared so the Closed-signal watcher (see `spawn_closed_watcher`)
    /// can hold its own reference for the process's lifetime while the
    /// command handlers here still borrow it for portal calls.
    session: Arc<Session<RemoteDesktop>>,
    /// Bumped every time the session is re-established (display change).
    /// A Closed-signal watcher is tagged with the generation it belongs
    /// to; when the old session is deliberately closed during a
    /// re-establish it must NOT bring the daemon down, so the watcher
    /// only exits the process if its generation is still current.
    generation: u64,
    /// PipeWire fd from the portal, kept owned for the daemon's
    /// lifetime. Each screenshot request `dup()`s it to get a fresh
    /// OwnedFd that pipewire-rs can consume (`connect_fd_rc` takes
    /// ownership). dup() works for any fd kind, including the
    /// socket-like fd the portal hands us — unlike re-opening via
    /// `/proc/self/fd/N`, which fails with ENXIO on non-reopenable
    /// fds.
    pw_fd: OwnedFd,
    /// Cached info for each portal stream, in portal order.  Includes
    /// the PipeWire node id (for screenshot) plus the stream's monitor
    /// rect (for `stream-at` queries that don't need the extension).
    streams: Vec<StreamInfo>,
    /// Serializes frame captures.  The screenshot handler drops the
    /// main state lock before capturing (so key/pointer commands aren't
    /// blocked for the seconds a capture takes), but two captures
    /// running at once stand up two PipeWire streams on the *same*
    /// nodes and collide — GNOME then fails both with "Buffer
    /// allocation failed".  This lock lets overlapping screenshots queue
    /// instead of colliding, without holding the main lock.  It's a
    /// separate Arc so a capture can hold it across `spawn_blocking`.
    capture_lock: Arc<Mutex<()>>,
}

/// Establish the portal session. May surface a consent dialog on
/// first run; subsequent daemon restarts re-prompt.
async fn establish_session() -> Result<(
    RemoteDesktop,
    Screencast,
    Session<RemoteDesktop>,
    OwnedFd,
    Vec<StreamInfo>,
)> {
    let rd = RemoteDesktop::new().await.context("RemoteDesktop proxy")?;
    let sc = Screencast::new().await.context("Screencast proxy")?;

    let session = rd
        .create_session(Default::default())
        .await
        .context("portal CreateSession")?;

    let rd_opts = SelectDevicesOptions::default()
        .set_devices(DeviceType::Keyboard | DeviceType::Pointer)
        .set_persist_mode(PersistMode::ExplicitlyRevoked);
    rd.select_devices(&session, rd_opts)
        .await
        .context("portal SelectDevices")?
        .response()
        .context("SelectDevices response")?;

    let sc_opts = SelectSourcesOptions::default()
        .set_sources(enumflags2::BitFlags::<SourceType>::from(SourceType::Monitor))
        .set_cursor_mode(CursorMode::Embedded)
        .set_multiple(true);
    sc.select_sources(&session, sc_opts)
        .await
        .context("portal Screencast SelectSources")?
        .response()
        .context("Screencast SelectSources response")?;

    let started = rd
        .start(&session, None, StartOptions::default())
        .await
        .context("portal Start")?
        .response()
        .context("Start response")?;

    let streams: Vec<StreamInfo> = started
        .streams()
        .iter()
        .map(|s| StreamInfo {
            node_id: s.pipe_wire_node_id(),
            position: s.position(),
            size: s.size(),
            frame_size: None,
        })
        .collect();
    if streams.is_empty() {
        return Err(anyhow!(
            "portal returned no streams — screencast consent denied or no monitor picked"
        ));
    }
    for (i, st) in streams.iter().enumerate() {
        eprintln!(
            "wayland-agent: stream[{}] node={} pos={:?} size={:?}",
            i, st.node_id, st.position, st.size
        );
    }

    let fd = sc
        .open_pipe_wire_remote(&session, OpenPipeWireRemoteOptions::default())
        .await
        .context("portal OpenPipeWireRemote")?;

    Ok((rd, sc, session, fd, streams))
}

/// dup() the supplied fd. Returns a new OwnedFd referring to the
/// same underlying open file description. Used to hand fresh
/// OwnedFds to pipewire-rs (which consumes them) without losing
/// the daemon's long-lived fd.
fn dup_fd(fd: &OwnedFd) -> Result<OwnedFd> {
    let raw = unsafe { libc::dup(fd.as_raw_fd()) };
    if raw < 0 {
        return Err(anyhow!("dup: {}", std::io::Error::last_os_error()));
    }
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

/// Prime each stream's physical frame size via a throwaway capture, so
/// the first click/move is scaled correctly on HiDPI monitors before
/// any screenshot has run. Best-effort: on failure the size is learned
/// lazily on the first real screenshot (1:1 until then). See
/// `pipewire_prime_frame_sizes_pub` for why this does a full capture
/// rather than a lighter format-only probe.
async fn prime_frame_sizes(fd: &OwnedFd, streams: &mut [StreamInfo]) {
    let node_ids: Vec<u32> = streams.iter().map(|s| s.node_id).collect();
    match dup_fd(fd) {
        Ok(probe_fd) => {
            let res = tokio::task::spawn_blocking(move || {
                crate::pipewire_prime_frame_sizes_pub(probe_fd, &node_ids)
            })
            .await;
            match res {
                Ok(Ok(dims)) => {
                    for (i, dim) in dims.iter().enumerate() {
                        streams[i].frame_size = Some(*dim);
                        eprintln!(
                            "wayland-agent: stream[{}] frame_size={:?} (logical size={:?})",
                            i, dim, streams[i].size
                        );
                    }
                }
                Ok(Err(e)) => eprintln!(
                    "wayland-agent: frame-size probe failed ({e:#}); \
                     will learn sizes lazily on first screenshot"
                ),
                Err(e) => eprintln!("wayland-agent: frame-size probe task panicked: {e}"),
            }
        }
        Err(e) => eprintln!("wayland-agent: could not dup fd for probe: {e:#}"),
    }
}

/// Establish a fresh portal session and prime its stream frame sizes.
/// Used at startup and again on every display reconfiguration; returns
/// the session already wrapped in an Arc (shared with its Closed
/// watcher).
async fn establish_and_prime() -> Result<(
    RemoteDesktop,
    Screencast,
    Arc<Session<RemoteDesktop>>,
    OwnedFd,
    Vec<StreamInfo>,
)> {
    let (rd, sc, session, fd, mut streams) = establish_session().await?;
    prime_frame_sizes(&fd, &mut streams).await;
    Ok((rd, sc, Arc::new(session), fd, streams))
}

/// Watch a session's Closed signal and exit the daemon when it fires —
/// unless that session has since been superseded by a re-establish (its
/// generation is stale), in which case the watcher just retires
/// quietly. Closing the old session during a re-establish is what makes
/// the generation guard necessary.
fn spawn_closed_watcher(
    session: Arc<Session<RemoteDesktop>>,
    generation: u64,
    state: Arc<Mutex<DaemonState>>,
    sock: PathBuf,
) {
    tokio::spawn(async move {
        match session.receive_closed().await {
            Ok(mut closed) => {
                let _ = closed.next().await;
                if state.lock().await.generation == generation {
                    eprintln!(
                        "wayland-agent: portal session closed (screen capture \
                         stopped or consent revoked); exiting"
                    );
                    let _ = std::fs::remove_file(&sock);
                    std::process::exit(0);
                }
                eprintln!(
                    "wayland-agent: superseded session (generation {generation}) closed \
                     after re-establish; watcher retiring"
                );
            }
            Err(e) => eprintln!(
                "wayland-agent: could not watch session Closed signal ({e:#}); \
                 daemon will not auto-exit when capture stops"
            ),
        }
    });
}

/// Re-establish the portal session after a display reconfiguration. The
/// cached streams and PipeWire fd from the old layout are dead once the
/// monitors change, so stand up a completely new session, prime it, and
/// swap it into the shared state. A monitor-selection consent dialog may
/// reappear — GNOME doesn't restore screencast streams from a token. The
/// old session is closed afterwards; its Closed watcher sees the bumped
/// generation and does not bring the daemon down.
async fn reestablish(state: &Arc<Mutex<DaemonState>>, sock: &PathBuf) -> Result<()> {
    // Build the new session WITHOUT holding the lock — it does several
    // portal round-trips and may block on a consent prompt.
    let (rd, sc, session, fd, streams) = establish_and_prime().await?;

    let (old_session, generation) = {
        let mut st = state.lock().await;
        st.rd = rd;
        st.sc = sc;
        st.pw_fd = fd;
        st.streams = streams;
        st.generation += 1;
        let generation = st.generation;
        let old = std::mem::replace(&mut st.session, session.clone());
        (old, generation)
    };

    spawn_closed_watcher(session, generation, state.clone(), sock.clone());

    // Free the old session's portal resources. This fires its Closed
    // signal, but that watcher now sees a stale generation and retires.
    let _ = old_session.close().await;
    eprintln!("wayland-agent: portal session re-established (generation {generation})");
    Ok(())
}

/// Watch GNOME/mutter for display reconfigurations and re-establish the
/// portal session when one happens, so the daemon survives a
/// resolution/scale/layout change instead of serving stale streams.
/// GNOME-specific (`org.gnome.Mutter.DisplayConfig`); on other
/// compositors the subscription simply fails and the daemon keeps its
/// "restart after a display change" behaviour.
fn spawn_display_watcher(state: Arc<Mutex<DaemonState>>, sock: PathBuf) {
    tokio::spawn(async move {
        let conn = match zbus::Connection::session().await {
            Ok(c) => c,
            Err(e) => {
                eprintln!(
                    "wayland-agent: no session bus for display watch ({e}); \
                     will not auto-re-establish on display change"
                );
                return;
            }
        };
        let proxy = match zbus::Proxy::new(
            &conn,
            "org.gnome.Mutter.DisplayConfig",
            "/org/gnome/Mutter/DisplayConfig",
            "org.gnome.Mutter.DisplayConfig",
        )
        .await
        {
            Ok(p) => p,
            Err(e) => {
                eprintln!(
                    "wayland-agent: DisplayConfig unavailable ({e}); \
                     will not auto-re-establish on display change"
                );
                return;
            }
        };
        let mut changes = match proxy.receive_signal("MonitorsChanged").await {
            Ok(s) => s,
            Err(e) => {
                eprintln!(
                    "wayland-agent: cannot watch MonitorsChanged ({e}); \
                     will not auto-re-establish on display change"
                );
                return;
            }
        };

        loop {
            // Block until the first change of a burst.
            if changes.next().await.is_none() {
                return; // signal stream ended (bus gone)
            }
            // Debounce: one reconfiguration emits several MonitorsChanged
            // in quick succession, and each re-establish may pop a consent
            // dialog — coalesce until 2s of quiet before acting.
            loop {
                match tokio::time::timeout(std::time::Duration::from_secs(2), changes.next()).await
                {
                    Ok(Some(_)) => continue,
                    Ok(None) => return,
                    Err(_) => break,
                }
            }
            eprintln!(
                "wayland-agent: display reconfiguration detected; re-establishing \
                 portal session (a monitor-selection prompt may appear)"
            );
            if let Err(e) = reestablish(&state, &sock).await {
                eprintln!(
                    "wayland-agent: re-establish after display change failed ({e:#}); \
                     streams may be stale until the daemon is restarted"
                );
            }
        }
    });
}

pub async fn run_daemon() -> Result<()> {
    let sock = socket_path()?;
    if sock.exists() {
        // Stale socket from a previous crash? Try connecting; if
        // it answers, refuse to start. Otherwise unlink.
        match tokio::net::UnixStream::connect(&sock).await {
            Ok(_) => return Err(anyhow!(
                "another wayland-agent daemon is already running at {}",
                sock.display()
            )),
            Err(_) => {
                let _ = std::fs::remove_file(&sock);
            }
        }
    }

    eprintln!("wayland-agent: establishing portal session (consent prompt may appear)...");
    let (rd, sc, session, fd, streams) = establish_and_prime().await?;
    eprintln!("wayland-agent: session ready, {} stream(s)", streams.len());

    let state = Arc::new(Mutex::new(DaemonState {
        rd, sc,
        session: session.clone(),
        pw_fd: fd,
        streams,
        capture_lock: Arc::new(Mutex::new(())),
        generation: 0,
    }));

    // Exit the daemon if the portal session is closed out from under us
    // (user hits "stop" on GNOME's screen-recording indicator, or
    // revokes consent); re-establish it if the display is reconfigured.
    spawn_closed_watcher(session, 0, state.clone(), sock.clone());
    spawn_display_watcher(state.clone(), sock.clone());

    let listener = UnixListener::bind(&sock).context("bind unix socket")?;
    let perms = std::fs::Permissions::from_mode(0o600);
    std::fs::set_permissions(&sock, perms).context("chmod socket")?;
    eprintln!("wayland-agent: listening on {}", sock.display());

    loop {
        let (stream, _addr) = listener.accept().await.context("accept")?;
        let state = state.clone();
        tokio::task::spawn(async move {
            if let Err(e) = handle_client(stream, state).await {
                eprintln!("wayland-agent: client error: {e:#}");
            }
        });
    }
}

async fn handle_client(stream: UnixStream, state: Arc<Mutex<DaemonState>>) -> Result<()> {
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let mut line = String::new();
    let bytes = reader.read_line(&mut line).await?;
    if bytes == 0 {
        return Ok(());
    }
    let req: Request = match serde_json::from_str(line.trim()) {
        Ok(r) => r,
        Err(e) => {
            let resp = Response::err(format!("bad request: {e}"));
            let mut buf = serde_json::to_vec(&resp)?;
            buf.push(b'\n');
            write_half.write_all(&buf).await?;
            return Ok(());
        }
    };
    let resp = dispatch(state, req).await;
    let resp = resp.unwrap_or_else(|e| Response::err(format!("{e:#}")));
    let mut buf = serde_json::to_vec(&resp)?;
    buf.push(b'\n');
    write_half.write_all(&buf).await?;
    Ok(())
}

async fn dispatch(state_arc: Arc<Mutex<DaemonState>>, req: Request) -> Result<Response> {
    let state = state_arc.lock().await;
    match req {
        Request::Ping => Ok(Response::ok_detail("pong".into())),
        Request::Streams => {
            let lines: Vec<String> = state
                .streams
                .iter()
                .enumerate()
                .map(|(i, s)| {
                    let pos = s
                        .position
                        .map(|(x, y)| format!("{x},{y}"))
                        .unwrap_or_else(|| "?".into());
                    let size = s
                        .size
                        .map(|(w, h)| format!("{w}x{h}"))
                        .unwrap_or_else(|| "?".into());
                    format!("{i}\t{node}\t{pos}\t{size}", node = s.node_id)
                })
                .collect();
            let body = if lines.is_empty() {
                "no streams".to_string()
            } else {
                format!("idx\tnode\tpos\tsize\n{}", lines.join("\n"))
            };
            Ok(Response::ok_detail(body))
        }
        Request::StreamAt { x, y } => {
            let idx = state
                .streams
                .iter()
                .position(|s| s.contains(x, y))
                .ok_or_else(|| anyhow!("no stream covers point ({x}, {y})"))?;
            Ok(Response::ok_detail(format!("{idx}")))
        }
        Request::Windows | Request::Window { .. } | Request::FocusWindow { .. }
        | Request::Monitors | Request::FindWindow { .. } => {
            // Drop the daemon state lock for D-Bus calls.
            drop(state);
            dispatch_extension(req).await
        }
        Request::ClickWindow { window, x, y, button, client } => {
            // Needs the extension (window lookup + focus) AND the portal
            // (pointer).  Drop the state lock for the D-Bus leg; the
            // handler re-locks for the pointer leg.
            drop(state);
            click_window(&state_arc, window, x, y, button, client).await
        }
        Request::TypeWindow { window, text, delay } => {
            // Same extension+portal split as ClickWindow.
            drop(state);
            type_window(&state_arc, window, text, delay).await
        }
        Request::UiTree { window, depth, all } => {
            // Extension (window lookup) + a11y bus only; no portal state.
            drop(state);
            ui_tree(&window, depth, all).await
        }
        Request::UiFind { window, pattern, role } => {
            drop(state);
            ui_find(&window, &pattern, role.as_deref()).await
        }
        Request::Key { name } => {
            let sym = crate::keysym_from_name(&name)
                .ok_or_else(|| anyhow!("unknown keysym {name:?}"))?;
            state.rd.notify_keyboard_keysym(
                &state.session, sym, KeyState::Pressed,
                NotifyKeyboardKeysymOptions::default(),
            ).await?;
            state.rd.notify_keyboard_keysym(
                &state.session, sym, KeyState::Released,
                NotifyKeyboardKeysymOptions::default(),
            ).await?;
            Ok(Response::ok())
        }
        Request::KeyDown { name } => {
            let sym = crate::keysym_from_name(&name)
                .ok_or_else(|| anyhow!("unknown keysym {name:?}"))?;
            state.rd.notify_keyboard_keysym(
                &state.session, sym, KeyState::Pressed,
                NotifyKeyboardKeysymOptions::default(),
            ).await?;
            Ok(Response::ok())
        }
        Request::KeyUp { name } => {
            let sym = crate::keysym_from_name(&name)
                .ok_or_else(|| anyhow!("unknown keysym {name:?}"))?;
            state.rd.notify_keyboard_keysym(
                &state.session, sym, KeyState::Released,
                NotifyKeyboardKeysymOptions::default(),
            ).await?;
            Ok(Response::ok())
        }
        Request::KeyChord { keys } => {
            let parts: Vec<&str> = keys.split('+').filter(|p| !p.is_empty()).collect();
            if parts.is_empty() {
                return Ok(Response::err("empty chord"));
            }
            let syms: Vec<i32> = parts
                .iter()
                .map(|p| {
                    crate::keysym_from_name(p)
                        .ok_or_else(|| anyhow!("unknown keysym in chord: {p:?}"))
                })
                .collect::<Result<_>>()?;
            // Press in order.
            for sym in &syms {
                state
                    .rd
                    .notify_keyboard_keysym(
                        &state.session,
                        *sym,
                        KeyState::Pressed,
                        NotifyKeyboardKeysymOptions::default(),
                    )
                    .await?;
            }
            // Release in reverse order so the modifier is the last to
            // come up — the held-modifier discipline emulators expect.
            for sym in syms.iter().rev() {
                state
                    .rd
                    .notify_keyboard_keysym(
                        &state.session,
                        *sym,
                        KeyState::Released,
                        NotifyKeyboardKeysymOptions::default(),
                    )
                    .await?;
            }
            Ok(Response::ok())
        }
        Request::KeyCode { code } => {
            state.rd.notify_keyboard_keycode(
                &state.session, code, KeyState::Pressed,
                NotifyKeyboardKeycodeOptions::default(),
            ).await?;
            state.rd.notify_keyboard_keycode(
                &state.session, code, KeyState::Released,
                NotifyKeyboardKeycodeOptions::default(),
            ).await?;
            Ok(Response::ok())
        }
        Request::Type { text, delay } => {
            type_text(&state, &text, delay).await?;
            Ok(Response::ok())
        }
        Request::Move { x, y, stream } => {
            let s = state.streams.get(stream)
                .ok_or_else(|| anyhow!("stream {stream} out of range"))?;
            let node = s.node_id;
            let (ix, iy) = s.screenshot_to_input(x, y);
            s.check_reachable(ix, iy)?;
            state.rd.notify_pointer_motion_absolute(
                &state.session, node, ix, iy,
                NotifyPointerMotionAbsoluteOptions::default(),
            ).await?;
            Ok(Response::ok())
        }
        Request::MoveGlobal { x, y } => {
            let (node, lx, ly) = resolve_global(&state.streams, x, y)?;
            state.rd.notify_pointer_motion_absolute(
                &state.session, node, lx, ly,
                NotifyPointerMotionAbsoluteOptions::default(),
            ).await?;
            Ok(Response::ok())
        }
        Request::Click { button } => {
            let code = crate::button_code(&button)?;
            state.rd.notify_pointer_button(
                &state.session, code, KeyState::Pressed,
                NotifyPointerButtonOptions::default(),
            ).await?;
            state.rd.notify_pointer_button(
                &state.session, code, KeyState::Released,
                NotifyPointerButtonOptions::default(),
            ).await?;
            Ok(Response::ok())
        }
        Request::ButtonDown { button } => {
            let code = crate::button_code(&button)?;
            state.rd.notify_pointer_button(
                &state.session, code, KeyState::Pressed,
                NotifyPointerButtonOptions::default(),
            ).await?;
            Ok(Response::ok())
        }
        Request::ButtonUp { button } => {
            let code = crate::button_code(&button)?;
            state.rd.notify_pointer_button(
                &state.session, code, KeyState::Released,
                NotifyPointerButtonOptions::default(),
            ).await?;
            Ok(Response::ok())
        }
        Request::ClickAt { x, y, button, stream } => {
            let s = state.streams.get(stream)
                .ok_or_else(|| anyhow!("stream {stream} out of range"))?;
            let node = s.node_id;
            let (ix, iy) = s.screenshot_to_input(x, y);
            s.check_reachable(ix, iy)?;
            let code = crate::button_code(&button)?;
            state.rd.notify_pointer_motion_absolute(
                &state.session, node, ix, iy,
                NotifyPointerMotionAbsoluteOptions::default(),
            ).await?;
            state.rd.notify_pointer_button(
                &state.session, code, KeyState::Pressed,
                NotifyPointerButtonOptions::default(),
            ).await?;
            state.rd.notify_pointer_button(
                &state.session, code, KeyState::Released,
                NotifyPointerButtonOptions::default(),
            ).await?;
            Ok(Response::ok())
        }
        Request::ClickAtGlobal { x, y, button } => {
            let (node, lx, ly) = resolve_global(&state.streams, x, y)?;
            let code = crate::button_code(&button)?;
            state.rd.notify_pointer_motion_absolute(
                &state.session, node, lx, ly,
                NotifyPointerMotionAbsoluteOptions::default(),
            ).await?;
            state.rd.notify_pointer_button(
                &state.session, code, KeyState::Pressed,
                NotifyPointerButtonOptions::default(),
            ).await?;
            state.rd.notify_pointer_button(
                &state.session, code, KeyState::Released,
                NotifyPointerButtonOptions::default(),
            ).await?;
            Ok(Response::ok())
        }
        Request::Screenshot { out } => {
            // Per-stream output paths.
            let outs: Vec<PathBuf> = if state.streams.len() == 1 {
                vec![out.clone()]
            } else {
                (0..state.streams.len())
                    .map(|i| {
                        let stem = out.file_stem().and_then(|s| s.to_str()).unwrap_or("frame");
                        let ext = out.extension().and_then(|s| s.to_str()).unwrap_or("png");
                        out.with_file_name(format!("{stem}-{i}.{ext}"))
                    })
                    .collect()
            };
            let node_ids: Vec<u32> = state.streams.iter().map(|s| s.node_id).collect();
            let fd_dup = dup_fd(&state.pw_fd)?;
            let capture_lock = state.capture_lock.clone();
            // Drop the main lock before going off to PipeWire — it
            // takes seconds and we don't want to block other
            // socket clients (key/pointer) during capture.
            drop(state);

            // Serialize captures: two PipeWire streams on the same nodes
            // at once collide ("Buffer allocation failed").  Overlapping
            // screenshots queue here instead.
            let _cap = capture_lock.lock().await;

            let outs_clone = outs.clone();
            let dims = tokio::task::spawn_blocking(move || {
                let refs: Vec<&std::path::Path> = outs_clone.iter().map(|p| p.as_path()).collect();
                crate::pipewire_capture_frames_pub(fd_dup, &node_ids, &refs)
            })
            .await
            .context("screenshot blocking task")??;

            // Cache the physical frame size per stream so subsequent
            // clicks can scale screenshot pixels into logical pointer
            // coords (see StreamInfo::screenshot_to_input).
            {
                let mut st = state_arc.lock().await;
                for (i, dim) in dims.iter().enumerate() {
                    if let Some(s) = st.streams.get_mut(i) {
                        s.frame_size = Some(*dim);
                    }
                }
            }

            Ok(Response::ok_paths(outs))
        }
        // Extension-required cases are handled in the outer dispatch
        // above (state lock released first); they never reach this
        // match arm.  Pattern omitted to silence "unreachable" warning.
    }
}

/* ============================================================ */
/*   Extension-backed dispatch                                  */
/*                                                              */
/*   These talk to the wayland-agent gnome-shell extension's    */
/*   D-Bus interface (com.mxshift.WaylandAgent).  If the        */
/*   extension isn't installed or enabled the connection fails  */
/*   immediately; we surface a clear error pointing at the      */
/*   install script.                                            */
/* ============================================================ */

const EXT_BUS_NAME: &str = "com.mxshift.WaylandAgent";
const EXT_OBJECT_PATH: &str = "/com/mxshift/WaylandAgent";
const EXT_INTERFACE: &str = "com.mxshift.WaylandAgent";

const EXT_NOT_FOUND_HINT: &str =
    "Run wayland-agent/gnome-extension/install.sh then log out and back \
     in so gnome-shell picks up the extension.";

async fn ext_proxy() -> Result<zbus::Proxy<'static>> {
    let conn = zbus::Connection::session()
        .await
        .context("session bus")?;
    let proxy = zbus::Proxy::new(
        &conn,
        EXT_BUS_NAME,
        EXT_OBJECT_PATH,
        EXT_INTERFACE,
    )
    .await
    .with_context(|| format!(
        "connect to {EXT_BUS_NAME} — extension not installed or not enabled.\n{EXT_NOT_FOUND_HINT}"
    ))?;
    Ok(proxy)
}

/// Render a zvariant value reasonably for human-eyed output.  zvariant
/// doesn't implement Display on OwnedValue/Value so we dispatch on the
/// common scalar variants explicitly and fall back to Debug for the
/// rest (arrays, dicts, structs).
fn render_value(v: &zvariant::OwnedValue) -> String {
    use zvariant::Value;
    let inner: &Value = &**v;
    match inner {
        Value::Str(s) => s.to_string(),
        Value::U64(n) => n.to_string(),
        Value::U32(n) => n.to_string(),
        Value::U16(n) => n.to_string(),
        Value::U8(n) => n.to_string(),
        Value::I64(n) => n.to_string(),
        Value::I32(n) => n.to_string(),
        Value::I16(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::F64(f) => format!("{f}"),
        Value::Signature(s) => s.to_string(),
        Value::ObjectPath(p) => p.to_string(),
        _ => format!("{inner:?}"),
    }
}

/// Format an `a{sv}` reply as a tab-separated key=value table.
fn dict_to_lines(dict: &std::collections::HashMap<String, zvariant::OwnedValue>) -> Vec<String> {
    let mut keys: Vec<&String> = dict.keys().collect();
    keys.sort();
    keys.into_iter()
        .map(|k| {
            let v = dict.get(k).unwrap();
            format!("{k}\t{}", render_value(v))
        })
        .collect()
}

fn fmt_dicts(label: &str, dicts: &[std::collections::HashMap<String, zvariant::OwnedValue>]) -> String {
    if dicts.is_empty() {
        return format!("no {label}");
    }
    let mut out = String::new();
    for (i, d) in dicts.iter().enumerate() {
        out.push_str(&format!("--- {label}[{i}] ---\n"));
        for line in dict_to_lines(d) {
            out.push_str(&line);
            out.push('\n');
        }
    }
    out.trim_end().to_string()
}

type WindowDict = std::collections::HashMap<String, zvariant::OwnedValue>;

/// Case-insensitive substring match against a window's wm_class,
/// app_id, and title — the find-window matching rule.
fn window_matches(w: &WindowDict, pattern: &str) -> bool {
    let needle = pattern.to_lowercase();
    ["wm_class", "app_id", "title"].iter().any(|k| {
        w.get(*k)
            .map(|v| render_value(v).to_lowercase().contains(&needle))
            .unwrap_or(false)
    })
}

fn dict_i64(w: &WindowDict, key: &str) -> Result<i64> {
    use zvariant::Value;
    let v = w.get(key).ok_or_else(|| anyhow!("window dict missing {key:?}"))?;
    Ok(match &**v {
        Value::U64(n) => *n as i64,
        Value::U32(n) => *n as i64,
        Value::I64(n) => *n,
        Value::I32(n) => *n as i64,
        other => return Err(anyhow!("window dict {key:?} is not an integer: {other:?}")),
    })
}

fn dict_bool(w: &WindowDict, key: &str) -> bool {
    matches!(w.get(key).map(|v| &**v), Some(zvariant::Value::Bool(true)))
}

/// One line per window — enough for a caller to pick an id.
fn summarize_windows(windows: &[WindowDict]) -> String {
    windows
        .iter()
        .map(|w| {
            let s = |k: &str| w.get(k).map(render_value).unwrap_or_default();
            format!(
                "  id={}\twm_class={:?}\tapp_id={:?}\tfocused={}\ttitle={:?}",
                s("id"),
                s("wm_class"),
                s("app_id"),
                s("focused"),
                s("title"),
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Resolve a `click-in` window selector against the current window
/// list: a string that parses as a u64 AND names an existing window id
/// wins; otherwise it's a find-window pattern that must match exactly
/// one window — several matches is the same loud error find-window
/// gives, so callers disambiguate instead of clicking into the wrong
/// window.
fn resolve_window_selector(windows: Vec<WindowDict>, sel: &str) -> Result<WindowDict> {
    if let Ok(id) = sel.parse::<i64>() {
        if let Some(w) = windows
            .iter()
            .find(|w| dict_i64(w, "id").map(|i| i == id).unwrap_or(false))
        {
            return Ok(w.clone());
        }
    }
    let mut matches: Vec<WindowDict> =
        windows.into_iter().filter(|w| window_matches(w, sel)).collect();
    match matches.len() {
        0 => Err(anyhow!("no window matched {sel:?}")),
        1 => Ok(matches.remove(0)),
        n => Err(anyhow!(
            "{n} windows match {sel:?} — refine the pattern or use a window id:\n{}",
            summarize_windows(&matches)
        )),
    }
}

/// Resolve a window selector against the current window list, focus
/// the window if it isn't already, and wait for focus to actually land
/// (re-reading geometry, which also picks up a post-raise/unminimize
/// move).  Some windows never take keyboard focus — proceed after the
/// deadline rather than failing.  Shared by `click-in` and `type-in`.
async fn resolve_and_focus(sel: &str) -> Result<WindowDict> {
    let proxy = ext_proxy().await?;
    let windows: Vec<WindowDict> = proxy.call("GetWindows", &()).await.map_err(|e| {
        anyhow!("GetWindows on com.mxshift.WaylandAgent failed: {e}\n{EXT_NOT_FOUND_HINT}")
    })?;
    let mut win = resolve_window_selector(windows, sel)?;
    let id = dict_i64(&win, "id")? as u64;

    if !dict_bool(&win, "focused") {
        let _: () = proxy.call("FocusWindow", &(id,)).await.map_err(|e| {
            anyhow!("FocusWindow on com.mxshift.WaylandAgent failed: {e}\n{EXT_NOT_FOUND_HINT}")
        })?;
        // Activation is asynchronous in mutter; poll until it lands.
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            win = proxy.call("GetWindow", &(id,)).await.map_err(|e| {
                anyhow!("GetWindow on com.mxshift.WaylandAgent failed after focus: {e}")
            })?;
            if dict_bool(&win, "focused") || tokio::time::Instant::now() >= deadline {
                break;
            }
        }
    }
    Ok(win)
}

/// The `click-in` implementation: resolve + focus the window, translate
/// the window-relative offset to a global-logical point, and click.
async fn click_window(
    state_arc: &Arc<Mutex<DaemonState>>,
    sel: String,
    x: f64,
    y: f64,
    button: String,
    client: bool,
) -> Result<Response> {
    let code = crate::button_code(&button)?;
    let win = resolve_and_focus(&sel).await?;
    let id = dict_i64(&win, "id")?;

    let (prefix, label) = if client { ("client", "client area") } else { ("frame", "frame") };
    let ox = dict_i64(&win, &format!("{prefix}_x"))? as f64;
    let oy = dict_i64(&win, &format!("{prefix}_y"))? as f64;
    let w = dict_i64(&win, &format!("{prefix}_w"))? as f64;
    let h = dict_i64(&win, &format!("{prefix}_h"))? as f64;
    if x < 0.0 || y < 0.0 || x >= w || y >= h {
        return Err(anyhow!(
            "offset ({x:.0}, {y:.0}) is outside window {id}'s {label} \
             ({w:.0}x{h:.0}). click-in coordinates are RELATIVE to the \
             window's origin, not global screen coordinates."
        ));
    }
    let (gx, gy) = (ox + x, oy + y);

    let state = state_arc.lock().await;
    let (node, fx, fy) = resolve_global(&state.streams, gx, gy)?;
    state.rd.notify_pointer_motion_absolute(
        &state.session, node, fx, fy,
        NotifyPointerMotionAbsoluteOptions::default(),
    ).await?;
    state.rd.notify_pointer_button(
        &state.session, code, KeyState::Pressed,
        NotifyPointerButtonOptions::default(),
    ).await?;
    state.rd.notify_pointer_button(
        &state.session, code, KeyState::Released,
        NotifyPointerButtonOptions::default(),
    ).await?;
    Ok(Response::ok_detail(format!(
        "clicked {button} at ({x:.0}, {y:.0}) relative to window {id}'s {label} \
         (global {gx:.0}, {gy:.0})"
    )))
}

/// Type `text` into whatever currently holds keyboard focus, one
/// press+release per character.  `delay` is milliseconds to wait after
/// each character — pacing for slow consumers (e.g. DOSBox's emulated
/// keyboard, which drops characters typed faster than it can drain).
async fn type_text(state: &DaemonState, text: &str, delay: Option<u64>) -> Result<()> {
    for ch in text.chars() {
        let sym = crate::keysym_for_char(ch)
            .ok_or_else(|| anyhow!("char {ch:?} has no mapped keysym"))?;
        state.rd.notify_keyboard_keysym(
            &state.session, sym, KeyState::Pressed,
            NotifyKeyboardKeysymOptions::default(),
        ).await?;
        state.rd.notify_keyboard_keysym(
            &state.session, sym, KeyState::Released,
            NotifyKeyboardKeysymOptions::default(),
        ).await?;
        if let Some(ms) = delay {
            tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
        }
    }
    Ok(())
}

/// The `type-in` implementation: resolve + focus the window, then type
/// into it.  No pointer movement — keyboard input follows focus, so
/// focusing is all the targeting `type` needs.
async fn type_window(
    state_arc: &Arc<Mutex<DaemonState>>,
    sel: String,
    text: String,
    delay: Option<u64>,
) -> Result<Response> {
    let win = resolve_and_focus(&sel).await?;
    let id = dict_i64(&win, "id")?;
    let nchars = text.chars().count();

    let state = state_arc.lock().await;
    type_text(&state, &text, delay).await?;
    Ok(Response::ok_detail(format!(
        "typed {nchars} character(s) into window {id}"
    )))
}

async fn dispatch_extension(req: Request) -> Result<Response> {
    let proxy = ext_proxy().await?;

    // Proxy creation is lazy on zbus — the actual "is the extension
    // running?" check happens at first .call().  Wrap call errors with
    // a hint pointing at the installer so users don't see a bare
    // org.freedesktop.DBus.Error.ServiceUnknown.
    match req {
        Request::Windows => {
            let windows: Vec<std::collections::HashMap<String, zvariant::OwnedValue>> =
                proxy.call("GetWindows", &()).await.map_err(|e| {
                    anyhow!("GetWindows on com.mxshift.WaylandAgent failed: {e}\n{EXT_NOT_FOUND_HINT}")
                })?;
            Ok(Response::ok_detail(fmt_dicts("window", &windows)))
        }
        Request::Window { id } => {
            let win: std::collections::HashMap<String, zvariant::OwnedValue> =
                proxy.call("GetWindow", &(id,)).await.map_err(|e| {
                    anyhow!("GetWindow on com.mxshift.WaylandAgent failed: {e}\n{EXT_NOT_FOUND_HINT}")
                })?;
            Ok(Response::ok_detail(fmt_dicts("window", &[win])))
        }
        Request::FocusWindow { id } => {
            let _: () = proxy.call("FocusWindow", &(id,)).await.map_err(|e| {
                anyhow!("FocusWindow on com.mxshift.WaylandAgent failed: {e}\n{EXT_NOT_FOUND_HINT}")
            })?;
            Ok(Response::ok())
        }
        Request::Monitors => {
            let monitors: Vec<std::collections::HashMap<String, zvariant::OwnedValue>> =
                proxy.call("GetMonitors", &()).await.map_err(|e| {
                    anyhow!("GetMonitors on com.mxshift.WaylandAgent failed: {e}\n{EXT_NOT_FOUND_HINT}")
                })?;
            Ok(Response::ok_detail(fmt_dicts("monitor", &monitors)))
        }
        Request::FindWindow { pattern, all } => {
            let windows: Vec<WindowDict> =
                proxy.call("GetWindows", &()).await.map_err(|e| {
                    anyhow!("GetWindows on com.mxshift.WaylandAgent failed: {e}\n{EXT_NOT_FOUND_HINT}")
                })?;
            let matches: Vec<WindowDict> = windows
                .into_iter()
                .filter(|w| window_matches(w, &pattern))
                .collect();
            match matches.len() {
                0 => Err(anyhow!("no window matched {pattern:?}")),
                1 => Ok(Response::ok_detail(fmt_dicts("match", &matches))),
                _ if all => Ok(Response::ok_detail(fmt_dicts("match", &matches))),
                n => Err(anyhow!(
                    "{n} windows match {pattern:?} — refine the pattern, target one \
                     by id (`window <id>` / `click-in <id> ...`), or pass --all to \
                     list every match:\n{}",
                    summarize_windows(&matches)
                )),
            }
        }
        _ => unreachable!("dispatch_extension called with non-extension request"),
    }
}

/* ============================================================ */
/*   AT-SPI2 (accessibility) dispatch                            */
/*                                                              */
/*   ui-tree / ui-find read another app's widget tree over the  */
/*   dedicated accessibility bus (AT-SPI2).  GTK/Qt/Firefox/    */
/*   Chromium expose trees; SDL/emulator/custom-toolkit apps    */
/*   expose nothing.  Coordinates: AT-SPI "window" coords are   */
/*   relative to the app's a11y toplevel; when the toplevel's   */
/*   SCREEN extents are honest (X11/XWayland apps) we translate */
/*   everything into OUR frame-relative space so the numbers    */
/*   feed straight into click-in.                               */
/* ============================================================ */

const ATSPI_ROOT_DEST: &str = "org.a11y.atspi.Registry";
const ATSPI_ROOT_PATH: &str = "/org/a11y/atspi/accessible/root";
const ATSPI_IFACE_ACC: &str = "org.a11y.atspi.Accessible";
const ATSPI_IFACE_COMP: &str = "org.a11y.atspi.Component";
/// StateType bit in word 0 of GetState: element is currently rendered.
const ATSPI_STATE_SHOWING: u32 = 1 << 25;
/// GetExtents coordinate types.
const ATSPI_COORD_SCREEN: u32 = 0;
const ATSPI_COORD_WINDOW: u32 = 1;
/// Hard cap on accessibles visited per walk — big apps (browsers)
/// expose tens of thousands of nodes and each costs D-Bus round-trips.
const UI_WALK_BUDGET: usize = 5000;
const UI_DEFAULT_DEPTH: u32 = 40;

#[derive(Clone, Debug)]
struct AccRef {
    dest: String,
    path: zvariant::OwnedObjectPath,
}

/// Connect to the dedicated accessibility bus (its address comes from
/// org.a11y.Bus on the session bus).
async fn a11y_connection() -> Result<zbus::Connection> {
    let session = zbus::Connection::session().await.context("session bus")?;
    let reply = session
        .call_method(
            Some("org.a11y.Bus"), "/org/a11y/bus", Some("org.a11y.Bus"), "GetAddress", &(),
        )
        .await
        .context("org.a11y.Bus.GetAddress — is the accessibility stack running?")?;
    let addr: String = reply.body().deserialize()?;
    zbus::connection::Builder::address(addr.as_str())?
        .build()
        .await
        .with_context(|| format!("connect to accessibility bus at {addr}"))
}

async fn acc_children(conn: &zbus::Connection, r: &AccRef) -> Result<Vec<AccRef>> {
    let reply = conn
        .call_method(Some(r.dest.as_str()), &r.path, Some(ATSPI_IFACE_ACC), "GetChildren", &())
        .await?;
    let kids: Vec<(String, zvariant::OwnedObjectPath)> = reply.body().deserialize()?;
    Ok(kids
        .into_iter()
        .filter(|(_, p)| p.as_str() != "/org/a11y/atspi/null")
        .map(|(dest, path)| AccRef { dest, path })
        .collect())
}

async fn acc_name(conn: &zbus::Connection, r: &AccRef) -> String {
    let reply = conn
        .call_method(
            Some(r.dest.as_str()), &r.path,
            Some("org.freedesktop.DBus.Properties"), "Get",
            &(ATSPI_IFACE_ACC, "Name"),
        )
        .await;
    match reply {
        Ok(m) => m
            .body()
            .deserialize::<zvariant::OwnedValue>()
            .ok()
            .and_then(|v| String::try_from(v).ok())
            .unwrap_or_default(),
        Err(_) => String::new(),
    }
}

async fn acc_role(conn: &zbus::Connection, r: &AccRef) -> String {
    match conn
        .call_method(Some(r.dest.as_str()), &r.path, Some(ATSPI_IFACE_ACC), "GetRoleName", &())
        .await
    {
        Ok(m) => m.body().deserialize().unwrap_or_else(|_| "?".into()),
        Err(_) => "?".into(),
    }
}

/// Is the element currently rendered?  Errors default to true so a
/// flaky app hides nothing.
async fn acc_showing(conn: &zbus::Connection, r: &AccRef) -> bool {
    match conn
        .call_method(Some(r.dest.as_str()), &r.path, Some(ATSPI_IFACE_ACC), "GetState", &())
        .await
    {
        Ok(m) => m
            .body()
            .deserialize::<Vec<u32>>()
            .ok()
            .and_then(|words| words.first().copied())
            .map(|w| w & ATSPI_STATE_SHOWING != 0)
            .unwrap_or(true),
        Err(_) => true,
    }
}

/// (x, y, w, h) in the requested AT-SPI coordinate space; None when the
/// element has no Component interface (structural nodes).
async fn acc_extents(conn: &zbus::Connection, r: &AccRef, coord: u32) -> Option<(i32, i32, i32, i32)> {
    let m = conn
        .call_method(Some(r.dest.as_str()), &r.path, Some(ATSPI_IFACE_COMP), "GetExtents", &(coord,))
        .await
        .ok()?;
    m.body().deserialize::<((i32, i32, i32, i32),)>().ok().map(|(t,)| t)
}

async fn a11y_app_pid(conn: &zbus::Connection, dest: &str) -> Option<u32> {
    let m = conn
        .call_method(
            Some("org.freedesktop.DBus"), "/org/freedesktop/DBus",
            Some("org.freedesktop.DBus"), "GetConnectionUnixProcessID", &(dest,),
        )
        .await
        .ok()?;
    m.body().deserialize().ok()
}

/// Find the AT-SPI applications that could belong to an extension
/// window dict, best match first.  Primary key is the pid; fallback is
/// a name match against wm_class/app_id (flatpak apps sit behind
/// xdg-dbus-proxy, so their bus pid is the proxy's, not the app's).
/// Returns a list because one app can register several bus connections
/// (86Box under flatpak registers two, only one of which exposes
/// windows) — the caller keeps the first candidate with toplevels.
async fn a11y_find_apps(conn: &zbus::Connection, win: &WindowDict) -> Result<Vec<AccRef>> {
    let root = AccRef {
        dest: ATSPI_ROOT_DEST.into(),
        path: zvariant::OwnedObjectPath::try_from(ATSPI_ROOT_PATH)?,
    };
    let apps = acc_children(conn, &root).await.context("list AT-SPI applications")?;
    let win_pid = dict_i64(win, "pid").ok();
    let targets: Vec<String> = ["wm_class", "app_id"]
        .iter()
        .filter_map(|k| win.get(*k).map(|v| render_value(v).to_lowercase()))
        .filter(|s| !s.is_empty())
        .collect();

    let mut by_pid = Vec::new();
    let mut by_name = Vec::new();
    let mut names = Vec::new();
    for a in &apps {
        if win_pid.is_some() && a11y_app_pid(conn, &a.dest).await == win_pid.map(|p| p as u32) {
            by_pid.push(a.clone());
            continue;
        }
        let name = acc_name(conn, a).await;
        if name.is_empty() {
            continue;
        }
        let ln = name.to_lowercase();
        if targets.iter().any(|t| t.contains(&ln) || ln.contains(t.as_str())) {
            by_name.push(a.clone());
        } else {
            names.push(name);
        }
    }
    by_pid.extend(by_name);
    if by_pid.is_empty() {
        return Err(anyhow!(
            "no AT-SPI application matches this window (pid {win_pid:?}) — the app \
             probably doesn't expose accessibility info (SDL/emulator/custom-toolkit \
             apps don't). Apps currently on the a11y bus: {}",
            if names.is_empty() { "none".into() } else { names.join(", ") }
        ));
    }
    Ok(by_pid)
}

/// Pick the a11y toplevel matching the extension window's title,
/// trying each candidate app connection until one exposes windows.
async fn a11y_find_toplevel(
    conn: &zbus::Connection,
    apps: &[AccRef],
    title: &str,
) -> Result<AccRef> {
    let mut tops = Vec::new();
    for app in apps {
        tops = acc_children(conn, app).await.context("list application toplevels")?;
        if !tops.is_empty() {
            break;
        }
    }
    match tops.len() {
        0 => return Err(anyhow!("application exposes no windows on the a11y bus")),
        1 => return Ok(tops[0].clone()),
        _ => {}
    }
    let mut names = Vec::new();
    for t in &tops {
        let name = acc_name(conn, t).await;
        if name == title {
            return Ok(t.clone());
        }
        names.push(name);
    }
    // No exact title match: a single SHOWING toplevel is unambiguous.
    let mut showing = Vec::new();
    for t in &tops {
        if acc_showing(conn, t).await {
            showing.push(t.clone());
        }
    }
    if showing.len() == 1 {
        return Ok(showing.remove(0));
    }
    Err(anyhow!(
        "none of the app's {} a11y toplevels matches title {title:?}: {names:?}",
        tops.len()
    ))
}

/// Offset of the a11y toplevel's origin within OUR frame rect, when the
/// app's SCREEN coordinates are trustworthy (X11/XWayland apps report
/// honest global coords; Wayland CSD apps report surface-relative junk,
/// which lands outside the frame rect and yields None).
async fn a11y_frame_offset(
    conn: &zbus::Connection,
    top: &AccRef,
    win: &WindowDict,
) -> Option<(i32, i32)> {
    let (sx, sy, _, _) = acc_extents(conn, top, ATSPI_COORD_SCREEN).await?;
    let fx = dict_i64(win, "frame_x").ok()? as i32;
    let fy = dict_i64(win, "frame_y").ok()? as i32;
    let fw = dict_i64(win, "frame_w").ok()? as i32;
    let fh = dict_i64(win, "frame_h").ok()? as i32;
    let (dx, dy) = (sx - fx, sy - fy);
    if dx >= 0 && dy >= 0 && dx < fw && dy < fh { Some((dx, dy)) } else { None }
}

struct UiNode {
    depth: usize,
    role: String,
    name: String,
    rect: Option<(i32, i32, i32, i32)>,
    showing: bool,
}

/// Depth-first walk of an a11y subtree in child order.  Returns the
/// visited nodes plus whether the walk hit the node budget.  Skips (and
/// doesn't descend into) non-SHOWING elements unless `include_hidden`.
async fn a11y_walk(
    conn: &zbus::Connection,
    top: &AccRef,
    max_depth: usize,
    include_hidden: bool,
) -> Result<(Vec<UiNode>, bool)> {
    let mut out = Vec::new();
    let mut stack = vec![(top.clone(), 0usize)];
    let mut visited = 0usize;
    let mut truncated = false;
    while let Some((r, depth)) = stack.pop() {
        visited += 1;
        if visited > UI_WALK_BUDGET {
            truncated = true;
            break;
        }
        let showing = acc_showing(conn, &r).await;
        if !showing && !include_hidden {
            continue;
        }
        out.push(UiNode {
            depth,
            role: acc_role(conn, &r).await,
            name: acc_name(conn, &r).await,
            rect: acc_extents(conn, &r, ATSPI_COORD_WINDOW).await,
            showing,
        });
        if depth < max_depth {
            for k in acc_children(conn, &r).await.unwrap_or_default().into_iter().rev() {
                stack.push((k, depth + 1));
            }
        }
    }
    Ok((out, truncated))
}

/// Shared front half of ui-tree/ui-find: resolve the window through the
/// extension, find its a11y app + toplevel, and work out the coordinate
/// translation.  Returns (connection, toplevel, window id, frame offset).
async fn ui_query_common(sel: &str) -> Result<(zbus::Connection, AccRef, i64, Option<(i32, i32)>)> {
    let proxy = ext_proxy().await?;
    let windows: Vec<WindowDict> = proxy.call("GetWindows", &()).await.map_err(|e| {
        anyhow!("GetWindows on com.mxshift.WaylandAgent failed: {e}\n{EXT_NOT_FOUND_HINT}")
    })?;
    let win = resolve_window_selector(windows, sel)?;
    let id = dict_i64(&win, "id")?;
    let title = win.get("title").map(render_value).unwrap_or_default();

    let conn = a11y_connection().await?;
    let apps = a11y_find_apps(&conn, &win).await?;
    let top = a11y_find_toplevel(&conn, &apps, &title).await?;
    let off = a11y_frame_offset(&conn, &top, &win).await;
    Ok((conn, top, id, off))
}

/// Header line telling the caller what space the printed coordinates
/// are in, and how to click them.
fn ui_coord_header(id: i64, off: Option<(i32, i32)>) -> String {
    match off {
        Some(_) => format!(
            "coords are relative to window {id}'s frame — click with \
             `click-in {id} <x> <y>`"
        ),
        None => format!(
            "coords are relative to the app's a11y toplevel (its screen \
             position is unverifiable — typical for Wayland-native apps); \
             for CSD apps this usually equals window {id}'s frame space \
             (`click-in {id} <x> <y>`) — verify against a screenshot"
        ),
    }
}

fn ui_translate(rect: (i32, i32, i32, i32), off: Option<(i32, i32)>) -> (i32, i32, i32, i32) {
    let (dx, dy) = off.unwrap_or((0, 0));
    (rect.0 + dx, rect.1 + dy, rect.2, rect.3)
}

pub(crate) async fn ui_tree(sel: &str, depth: Option<u32>, all: bool) -> Result<Response> {
    let (conn, top, id, off) = ui_query_common(sel).await?;
    let max_depth = depth.unwrap_or(UI_DEFAULT_DEPTH) as usize;
    let (nodes, truncated) = a11y_walk(&conn, &top, max_depth, all).await?;

    let mut out = ui_coord_header(id, off);
    out.push('\n');
    for n in &nodes {
        out.push_str(&"  ".repeat(n.depth));
        out.push_str(&n.role);
        if !n.name.is_empty() {
            out.push_str(&format!(" {:?}", n.name));
        }
        // Coordinates of non-SHOWING elements are meaningless (Qt
        // reports popped-down menus at garbage positions) — print the
        // tag, not numbers an agent might click.
        if n.showing {
            if let Some(r) = n.rect {
                let (x, y, w, h) = ui_translate(r, off);
                out.push_str(&format!(" ({x},{y} {w}x{h})"));
            }
        } else {
            out.push_str(" [hidden]");
        }
        out.push('\n');
    }
    if truncated {
        out.push_str(&format!(
            "... truncated at {UI_WALK_BUDGET} elements — use --depth or ui-find\n"
        ));
    }
    Ok(Response::ok_detail(out.trim_end().to_string()))
}

pub(crate) async fn ui_find(sel: &str, pattern: &str, role: Option<&str>) -> Result<Response> {
    let (conn, top, id, off) = ui_query_common(sel).await?;
    // Search everything, including popped-down menus — knowing a hidden
    // element exists is the point of searching.
    let (nodes, truncated) = a11y_walk(&conn, &top, UI_DEFAULT_DEPTH as usize, true).await?;

    let needle = pattern.to_lowercase();
    let role_needle = role.map(|r| r.to_lowercase());
    let hits: Vec<&UiNode> = nodes
        .iter()
        .filter(|n| n.name.to_lowercase().contains(&needle))
        .filter(|n| role_needle.as_deref().is_none_or(|r| n.role.to_lowercase() == r))
        .collect();

    if hits.is_empty() {
        return Err(anyhow!(
            "no UI element matched name {pattern:?}{} in window {id}{} — run \
             `ui-tree {id}` to see what the app exposes",
            role.map(|r| format!(" with role {r:?}")).unwrap_or_default(),
            if truncated { " (walk truncated — the tree is very large)" } else { "" },
        ));
    }

    let mut out = ui_coord_header(id, off);
    out.push('\n');
    for n in hits {
        out.push_str(&n.role);
        out.push_str(&format!(" {:?}", n.name));
        // See ui_tree: hidden elements get the tag, not garbage coords.
        if n.showing {
            if let Some(r) = n.rect {
                let (x, y, w, h) = ui_translate(r, off);
                out.push_str(&format!(
                    " center=({},{}) rect=({x},{y} {w}x{h})",
                    x + w / 2,
                    y + h / 2
                ));
            }
        } else {
            out.push_str(" [hidden — open its menu/pane first, then re-run]");
        }
        out.push('\n');
    }
    if truncated {
        out.push_str("... walk truncated — matches beyond the budget were not seen\n");
    }
    Ok(Response::ok_detail(out.trim_end().to_string()))
}

/// Connect to the daemon and send one request, return its response.
pub async fn client_send(req: &Request) -> Result<Response> {
    let sock = socket_path()?;
    let stream = UnixStream::connect(&sock).await.with_context(|| {
        format!("connecting to {} — is `wayland-agent daemon` running?", sock.display())
    })?;
    let (read_half, mut write_half) = stream.into_split();
    let mut buf = serde_json::to_vec(req)?;
    buf.push(b'\n');
    write_half.write_all(&buf).await?;
    drop(write_half);
    let mut reader = BufReader::new(read_half);
    let mut line = String::new();
    reader.read_line(&mut line).await?;
    let resp: Response = serde_json::from_str(line.trim()).context("decoding daemon response")?;
    Ok(resp)
}

#[allow(dead_code)] // The HashMap import is keyed for future commands.
fn _hm_keep(_x: HashMap<u8, u8>) {}

#[cfg(test)]
mod tests {
    use super::*;
    use zvariant::{OwnedValue, Value};

    fn win(id: u64, wm_class: &str, title: &str, focused: bool) -> WindowDict {
        let mut w = WindowDict::new();
        w.insert("id".into(), OwnedValue::try_from(Value::U64(id)).unwrap());
        w.insert("wm_class".into(), OwnedValue::try_from(Value::new(wm_class)).unwrap());
        w.insert("app_id".into(), OwnedValue::try_from(Value::new("")).unwrap());
        w.insert("title".into(), OwnedValue::try_from(Value::new(title)).unwrap());
        w.insert("focused".into(), OwnedValue::try_from(Value::Bool(focused)).unwrap());
        w
    }

    #[test]
    fn match_is_case_insensitive_substring() {
        let w = win(1, "dosbox-x", "DOSBox-X 2024", false);
        assert!(window_matches(&w, "DOSBox"));
        assert!(window_matches(&w, "2024"));
        assert!(!window_matches(&w, "firefox"));
    }

    #[test]
    fn selector_prefers_exact_id() {
        // "2" is both a valid id and a substring of the other title.
        let ws = vec![win(1, "term", "window 2", false), win(2, "editor", "e", false)];
        let hit = resolve_window_selector(ws, "2").unwrap();
        assert_eq!(dict_i64(&hit, "id").unwrap(), 2);
    }

    #[test]
    fn selector_falls_back_to_pattern_when_id_unknown() {
        let ws = vec![win(1, "term-99", "t", false)];
        let hit = resolve_window_selector(ws, "99").unwrap();
        assert_eq!(dict_i64(&hit, "id").unwrap(), 1);
    }

    #[test]
    fn ambiguous_selector_errors_with_candidates() {
        let ws = vec![win(1, "term", "a", true), win(2, "term", "b", false)];
        let err = resolve_window_selector(ws, "term").unwrap_err().to_string();
        assert!(err.contains("2 windows match"), "{err}");
        assert!(err.contains("id=1"), "{err}");
        assert!(err.contains("id=2"), "{err}");
    }

    #[test]
    fn unmatched_selector_errors() {
        let ws = vec![win(1, "term", "a", false)];
        assert!(resolve_window_selector(ws, "nope").is_err());
    }

    /// Live end-to-end test against the running gnome-shell extension
    /// and accessibility bus — run explicitly with
    /// `cargo test ui_tree_live -- --ignored --nocapture`.
    /// Needs at least one AT-SPI-exposing app with an open window.
    #[tokio::test]
    #[ignore]
    async fn ui_tree_live() {
        let resp = ui_tree("86box", Some(6), false).await;
        match resp {
            Ok(Response::Ok { detail: Some(d), .. }) => {
                println!("{d}");
                assert!(d.lines().count() > 1, "expected at least one tree node");
            }
            other => panic!("ui_tree failed: {other:?}"),
        }
    }

    #[tokio::test]
    #[ignore]
    async fn ui_find_live() {
        let resp = ui_find("86box", "", None).await;
        match resp {
            Ok(Response::Ok { detail: Some(d), .. }) => println!("{d}"),
            other => panic!("ui_find failed: {other:?}"),
        }
    }

    #[test]
    fn dict_accessors() {
        let w = win(7, "x", "y", true);
        assert_eq!(dict_i64(&w, "id").unwrap(), 7);
        assert!(dict_bool(&w, "focused"));
        assert!(!dict_bool(&w, "missing"));
        assert!(dict_i64(&w, "missing").is_err());
    }
}
