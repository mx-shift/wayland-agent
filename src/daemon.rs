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
    /// Type a UTF-8 string by mapping each char to its keysym.
    Type { text: String },
    /// Absolute pointer move on the given stream.  `x`/`y` are in
    /// screenshot-pixel space of that stream (what you read off the
    /// PNG); the daemon scales them to the portal's logical space.
    Move { x: f64, y: f64, stream: usize },
    /// Press+release a pointer button at the current position.
    Click { button: String },
    /// Move + press + release, in screenshot-pixel space of `stream`.
    ClickAt { x: f64, y: f64, button: String, stream: usize },
    /// Absolute pointer move in **global logical** coords (the space
    /// the extension reports window/monitor rects in).  The daemon
    /// resolves which stream covers the point and subtracts its origin;
    /// no scaling is applied (global coords are already logical).
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
    /// Find the first window whose wm_class/app_id/title matches `pattern`.
    /// Match is case-insensitive substring.
    FindWindow { pattern: String },
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
///   coordinates in the stream's **logical** space (i.e. `size`).
///
/// So a pixel read off a screenshot (physical space) must be scaled by
/// `size / frame_size` before it is a valid pointer coordinate.  That
/// ratio is the "multiplier" callers kept reinventing; the daemon now
/// applies it internally (see `screenshot_to_input`) so every command
/// takes plain screenshot-pixel coordinates.
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
    /// Convert a screenshot-pixel coordinate (physical space, what a
    /// caller reads off the PNG) into the logical pointer coordinate the
    /// RemoteDesktop portal expects.  Uses the cached `frame_size`
    /// (physical) vs `size` (logical) ratio; if either is unknown the
    /// conversion is 1:1 — correct for unscaled monitors, and the only
    /// case where a pre-screenshot click on a scaled monitor could still
    /// be off (take a screenshot first to prime the ratio).
    pub fn screenshot_to_input(&self, x: f64, y: f64) -> (f64, f64) {
        match (self.size, self.frame_size) {
            (Some((lw, lh)), Some((fw, fh))) if fw > 0 && fh > 0 => {
                (x * lw as f64 / fw as f64, y * lh as f64 / fh as f64)
            }
            _ => (x, y),
        }
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

/// Resolve a global logical coordinate to (node_id, local_x, local_y).
/// Finds the stream whose logical rect covers (x, y) and subtracts its
/// origin.  Global coords are already logical, so no scaling — this is
/// the path for coordinates that come from the gnome-shell extension
/// (`windows`/`find-window`/`monitors`), not from a screenshot.
fn resolve_global(streams: &[StreamInfo], x: f64, y: f64) -> Result<(u32, f64, f64)> {
    let s = streams
        .iter()
        .find(|s| s.contains(x, y))
        .ok_or_else(|| anyhow!("no stream covers global point ({x}, {y})"))?;
    let (px, py) = s.position.ok_or_else(|| anyhow!("stream has no position"))?;
    Ok((s.node_id, x - px as f64, y - py as f64))
}

/// Shared state held across socket connections. Wrapped in a Mutex so
/// we serialize portal calls — ashpd futures are !Send across
/// awaits in some cases, and we don't want to interleave
/// pointer/key events anyway (one client at a time keeps semantics
/// predictable).
struct DaemonState {
    rd: RemoteDesktop,
    sc: Screencast,
    session: Session<RemoteDesktop>,
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
    let (rd, sc, session, fd, mut streams) = establish_session().await?;
    eprintln!("wayland-agent: session ready, {} stream(s)", streams.len());

    // Prime the physical frame size of each stream now, so the first
    // click/move is scaled correctly on HiDPI monitors before any
    // screenshot has run. This does a throwaway capture (pixels
    // discarded) — the same path a real screenshot uses, which is the
    // only one GNOME's screencast tears down cleanly. Non-fatal: on
    // failure we fall back to learning the size lazily on the first
    // screenshot (1:1 until then).
    {
        let node_ids: Vec<u32> = streams.iter().map(|s| s.node_id).collect();
        match dup_fd(&fd) {
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

    let state = Arc::new(Mutex::new(DaemonState {
        rd, sc, session,
        pw_fd: fd,
        streams,
        capture_lock: Arc::new(Mutex::new(())),
    }));

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
        Request::Type { text } => {
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
            }
            Ok(Response::ok())
        }
        Request::Move { x, y, stream } => {
            let s = state.streams.get(stream)
                .ok_or_else(|| anyhow!("stream {stream} out of range"))?;
            let node = s.node_id;
            let (ix, iy) = s.screenshot_to_input(x, y);
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
        Request::ClickAt { x, y, button, stream } => {
            let s = state.streams.get(stream)
                .ok_or_else(|| anyhow!("stream {stream} out of range"))?;
            let node = s.node_id;
            let (ix, iy) = s.screenshot_to_input(x, y);
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
        Request::FindWindow { pattern } => {
            let windows: Vec<std::collections::HashMap<String, zvariant::OwnedValue>> =
                proxy.call("GetWindows", &()).await.map_err(|e| {
                    anyhow!("GetWindows on com.mxshift.WaylandAgent failed: {e}\n{EXT_NOT_FOUND_HINT}")
                })?;
            let needle = pattern.to_lowercase();
            let hit = windows.into_iter().find(|w| {
                for k in ["wm_class", "app_id", "title"] {
                    if let Some(v) = w.get(k) {
                        let s = render_value(v).to_lowercase();
                        if s.contains(&needle) {
                            return true;
                        }
                    }
                }
                false
            });
            match hit {
                Some(w) => Ok(Response::ok_detail(fmt_dicts("match", &[w]))),
                None => Err(anyhow!("no window matched {pattern:?}")),
            }
        }
        _ => unreachable!("dispatch_extension called with non-extension request"),
    }
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
