//! wayland-agent: a minimal CLI for driving keyboard input AND
//! capturing the screen on a GNOME/Wayland session from a non-GUI
//! shell. Uses the freedesktop RemoteDesktop + Screencast portals.
//!
//! Architecture: one persistent daemon owns the portal session and
//! the PipeWire fd; every other subcommand (`key`, `type`, `click`,
//! `screenshot`, ...) is a thin client that connects to
//! `$XDG_RUNTIME_DIR/wayland-agent.sock` and sends one JSON request.
//!
//! Run `wayland-agent daemon` once (foreground or via a systemd-user
//! unit). First start surfaces the portal consent dialog — accept it.
//! Subsequent calls reuse the running session.

use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

mod daemon;

use anyhow::{Context, Result, anyhow};
use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    about = "Drive keyboard input and capture the screen on a GNOME/Wayland session via portals.",
    long_about = "Two categories of subcommands:\n\
                  \n\
                  [portal]  Uses only the freedesktop RemoteDesktop + ScreenCast portals.  \
                            Works on any Wayland session that exposes them (GNOME, KDE, \
                            wlroots).  Requires only the one-time portal consent at daemon \
                            start.\n\
                  \n\
                  [ext]     Requires the wayland-agent gnome-shell extension \
                            (gnome-extension/install.sh in this repo).  GNOME gates its \
                            built-in window-introspection D-Bus interface behind a hardcoded \
                            caller whitelist, so the extension is what unlocks window \
                            enumeration, focus control, and monitor metadata for \
                            unprivileged callers.  Without it, [ext] commands fail with a \
                            clear error pointing at the installer.\n\
                  \n\
                  All commands except `daemon`/`ping` go through the daemon socket.  Start \
                  the daemon once with `wayland-agent daemon` (consent prompt on first run); \
                  every subsequent CLI call is near-instant socket IO."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /* ----- meta / lifecycle ----- */

    /// Run as a persistent daemon. First start surfaces the
    /// freedesktop portal consent dialog; subsequent CLI commands
    /// reuse the same session.
    Daemon,

    /// [portal] Liveness check — returns "pong" if the daemon is up.
    Ping,

    /* ----- [portal]  keyboard ----- */

    /// [portal] Press+release a single keysym by name (e.g. `space`,
    /// `Return`, `a`).
    Key { name: String },

    /// [portal] Press+release a chord of keysyms separated by `+`
    /// (e.g. `Ctrl+F4`, `F12+o`).  Keys are pressed in left-to-right
    /// order then released in reverse — the modifier-held semantics
    /// emulators expect.  Use this for DOSBox-X's swap-floppy hotkey
    /// and any app that distinguishes a held modifier from two
    /// independent presses.
    KeyChord { keys: String },

    /// [portal] Press+release a Linux evdev keycode directly.
    KeyCode { code: i32 },

    /// [portal] Press AND HOLD a keysym until a matching `key-up`.
    /// For apps that distinguish a held key (pinball plungers,
    /// accelerating cursors) from a tap.
    KeyDown { name: String },

    /// [portal] Release a keysym previously held with `key-down`.
    KeyUp { name: String },

    /// [portal] Type a UTF-8 string — each character becomes a
    /// press+release.  No way to compose modifier+key inside a string;
    /// use `key-chord` for combos.
    Type { text: String },

    /* ----- [portal]  pointer ----- */

    /// [portal] Move the pointer to (x, y) on the picked stream.
    /// Coordinates are screenshot pixels of that stream (0..W × 0..H of
    /// its PNG); the daemon scales them to the portal's logical space,
    /// so they match 1:1 with what you read off a `screenshot`.
    Move {
        x: f64,
        y: f64,
        #[arg(long, default_value_t = 0)]
        stream: usize,
    },

    /// [portal] Move the pointer to a GLOBAL logical coordinate — the
    /// space the extension's `windows`/`monitors` report rects in. The
    /// daemon picks the covering stream and subtracts its origin for
    /// you; no manual offset math, no scaling.
    MoveGlobal { x: f64, y: f64 },

    /// [portal] Press+release a pointer button at the current
    /// position.
    Click {
        #[arg(long, default_value = "left")]
        button: String,
    },

    /// [portal] Move pointer to (x, y) on the picked stream, then
    /// click.  Coordinates are screenshot pixels of that stream (same
    /// space as `screenshot` output).  Useful for focusing a window
    /// before chaining `key`/`type`.
    ClickAt {
        x: f64,
        y: f64,
        #[arg(long, default_value = "left")]
        button: String,
        #[arg(long, default_value_t = 0)]
        stream: usize,
    },

    /// [portal] Click at a GLOBAL logical coordinate — feed it
    /// `frame_x`/`frame_y` (or a point inside `client_rect`) straight
    /// from the extension's `find-window`/`windows` output.  The daemon
    /// resolves the stream and offset itself.
    ClickGlobal {
        x: f64,
        y: f64,
        #[arg(long, default_value = "left")]
        button: String,
    },

    /* ----- [portal]  capture ----- */

    /// [portal] Capture one frame per monitor stream.  Single stream:
    /// writes exactly `out`.  Multi-stream: writes `<stem>-N.<ext>`
    /// per stream — caller selects which file to read.
    Screenshot { out: PathBuf },

    /// [portal] List the daemon's open streams (index, PipeWire node,
    /// portal-reported position, size).  Position+size are global
    /// screen coords when the stream's source is a monitor.
    Streams,

    /// [portal] Print the stream index whose portal-reported rect
    /// covers screen point (x, y).  Useful for resolving a known
    /// window position (e.g. from `find-window`) to the right stream
    /// before screenshot/click/key.
    StreamAt { x: f64, y: f64 },

    /* ----- [ext]  window + monitor introspection ----- */

    /// [ext] List visible top-level windows with id, title, wm_class,
    /// app_id, pid, monitor index, frame_rect, client_rect, scale,
    /// focused/minimized/maximized/fullscreen flags.
    Windows,

    /// [ext] Get one window's metadata by id (from `windows`).
    Window { id: u64 },

    /// [ext] Activate (focus + raise) a window by id.
    Focus { id: u64 },

    /// [ext] List monitors with index, connector name (e.g. "DP-1"),
    /// global-screen rect, scale, primary flag.
    Monitors,

    /// [ext] Find the first window whose wm_class, app_id, or title
    /// contains the (case-insensitive) pattern.  Prints the window's
    /// full metadata dict.
    FindWindow { pattern: String },
}

pub(crate) fn button_code(name: &str) -> Result<i32> {
    // Linux evdev button codes (asm-generic/input-event-codes.h).
    Ok(match name {
        "left" | "1" => 0x110,
        "right" | "2" => 0x111,
        "middle" | "3" => 0x112,
        "back" | "8" => 0x116,
        "forward" | "9" => 0x117,
        _ => return Err(anyhow!("unknown button {name:?} (use left/right/middle/back/forward)")),
    })
}

/// Connect to PipeWire via the FD supplied by the screencast portal,
/// attach a stream to each supplied node, wait for one full frame
/// per node, write each as PNG to the matching output path. Runs
/// synchronously on its own thread (PipeWire's main loop is blocking
/// and not Tokio-compatible).
/// Returns the physical (width, height) of each captured frame, in the
/// same order as `node_ids`.  The daemon caches these so it can scale
/// screenshot-pixel click coordinates into the portal's logical space.
pub(crate) fn pipewire_capture_frames_pub(
    fd: OwnedFd,
    node_ids: &[u32],
    outs: &[&Path],
) -> Result<Vec<(u32, u32)>> {
    pipewire_capture_frames(fd, node_ids, Some(outs))
}

/// Capture one frame per node purely to learn each stream's physical
/// size, then discard the pixels. Returns (width, height) per node.
///
/// This deliberately reuses the full capture path — negotiate buffers,
/// receive one real frame, tear down cleanly — rather than a lighter
/// "just read the negotiated format" probe. A probe that quits during
/// format negotiation (before buffers are allocated) leaves GNOME's
/// screencast node with a half-allocated buffer pool, and every
/// subsequent capture then fails with "Buffer allocation failed". Doing
/// a real throwaway capture is the only teardown GNOME handles cleanly.
pub(crate) fn pipewire_prime_frame_sizes_pub(
    fd: OwnedFd,
    node_ids: &[u32],
) -> Result<Vec<(u32, u32)>> {
    pipewire_capture_frames(fd, node_ids, None)
}

/// Capture one frame per node. When `outs` is `Some`, each frame is
/// saved as a PNG to the matching path; when `None`, frames are
/// captured only to measure their physical size and then dropped.
/// Returns (width, height) per node in `node_ids` order.
fn pipewire_capture_frames(
    fd: OwnedFd,
    node_ids: &[u32],
    outs: Option<&[&Path]>,
) -> Result<Vec<(u32, u32)>> {
    if let Some(o) = outs {
        assert_eq!(node_ids.len(), o.len(), "node_ids/outs length mismatch");
    }
    // For single-stream we delegate to the original single-frame
    // path to keep the well-tested code working unchanged. Multi-
    // stream uses a fanout below.
    if node_ids.len() == 1 {
        let dim = pipewire_capture_one_frame_inner(fd, node_ids[0], outs.map(|o| o[0]))?;
        return Ok(vec![dim]);
    }
    pipewire_capture_many_inner(fd, node_ids, outs)
}

fn pipewire_capture_one_frame_inner(fd: OwnedFd, node_id: u32, out: Option<&Path>) -> Result<(u32, u32)> {
    use pipewire as pw;
    use pw::spa;
    use spa::pod::Pod;

    pw::init();

    let mainloop = pw::main_loop::MainLoopRc::new(None).context("pw main_loop")?;
    let context = pw::context::ContextRc::new(&mainloop, None).context("pw context")?;
    let core = context
        .connect_fd_rc(fd, None)
        .context("pw connect_fd")?;

    // Shared state passed into the per-stream listeners — the
    // negotiated video format, plus the captured RGBA frame once
    // we've seen one.
    #[derive(Default)]
    struct CaptureState {
        format: Option<spa::param::video::VideoInfoRaw>,
        captured: Option<(u32, u32, Vec<u8>)>,
    }
    use std::cell::RefCell;
    use std::rc::Rc;
    let state = Rc::new(RefCell::new(CaptureState::default()));

    let stream = pw::stream::StreamBox::new(
        &core,
        "wayland-agent-screenshot",
        pw::properties::properties! {
            *pw::keys::MEDIA_TYPE => "Video",
            *pw::keys::MEDIA_CATEGORY => "Capture",
            *pw::keys::MEDIA_ROLE => "Screen",
        },
    )
    .context("pw stream new")?;

    let main_for_quit = mainloop.clone();
    let state_for_param = state.clone();
    let state_for_process = state.clone();

    let _listener = stream
        .add_local_listener_with_user_data(())
        .state_changed(|_, _, old, new| {
            eprintln!("wayland-agent: pw state {:?} -> {:?}", old, new);
        })
        .param_changed(move |_stream, _ud, id, param| {
            let Some(param) = param else { return };
            if id != spa::param::ParamType::Format.as_raw() {
                return;
            }
            let (media_type, media_subtype) = match spa::param::format_utils::parse_format(param) {
                Ok(v) => v,
                Err(_) => return,
            };
            if media_type != spa::param::format::MediaType::Video
                || media_subtype != spa::param::format::MediaSubtype::Raw
            {
                return;
            }
            let mut info = spa::param::video::VideoInfoRaw::default();
            if info.parse(param).is_err() {
                return;
            }
            eprintln!(
                "wayland-agent: pw format {:?} {}x{} fr {}/{}",
                info.format(),
                info.size().width,
                info.size().height,
                info.framerate().num,
                info.framerate().denom,
            );
            state_for_param.borrow_mut().format = Some(info);
        })
        .process(move |stream, _ud| {
            let Some(mut buffer) = stream.dequeue_buffer() else { return };
            let datas = buffer.datas_mut();
            if datas.is_empty() {
                return;
            }
            let Some(format) = state_for_process.borrow().format else { return };

            let chunk = datas[0].chunk();
            let size = chunk.size() as usize;
            let stride = chunk.stride() as usize;
            let pix_format = format.format();
            let w = format.size().width as usize;
            let h = format.size().height as usize;
            let bpp = bytes_per_pixel(pix_format);
            if bpp == 0 {
                eprintln!(
                    "wayland-agent: unsupported pixel format {:?}, skipping",
                    pix_format
                );
                return;
            }
            // The first frame after format negotiation is usually
            // valid. If size is zero we got a metadata-only buffer;
            // wait for the next one.
            if size == 0 {
                return;
            }
            let Some(data) = datas[0].data() else { return };
            // Convert the buffer's pixel layout to RGBA8.
            let rgba = convert_to_rgba(data, w, h, stride, pix_format);
            state_for_process.borrow_mut().captured = Some((w as u32, h as u32, rgba));
            // We have what we need — exit the mainloop on next iter.
            main_for_quit.quit();
        })
        .register()
        .context("pw stream register")?;

    // Format negotiation pod: accept the formats we can decode in
    // convert_to_rgba below. Order matters — we ask for the
    // first-listed format first.
    let obj = pw::spa::pod::object!(
        pw::spa::utils::SpaTypes::ObjectParamFormat,
        pw::spa::param::ParamType::EnumFormat,
        pw::spa::pod::property!(
            pw::spa::param::format::FormatProperties::MediaType,
            Id,
            pw::spa::param::format::MediaType::Video
        ),
        pw::spa::pod::property!(
            pw::spa::param::format::FormatProperties::MediaSubtype,
            Id,
            pw::spa::param::format::MediaSubtype::Raw
        ),
        pw::spa::pod::property!(
            pw::spa::param::format::FormatProperties::VideoFormat,
            Choice,
            Enum,
            Id,
            pw::spa::param::video::VideoFormat::BGRx,
            pw::spa::param::video::VideoFormat::BGRx,
            pw::spa::param::video::VideoFormat::RGBx,
            pw::spa::param::video::VideoFormat::RGBA,
            pw::spa::param::video::VideoFormat::BGRA,
            pw::spa::param::video::VideoFormat::RGB,
            pw::spa::param::video::VideoFormat::BGR
        ),
        pw::spa::pod::property!(
            pw::spa::param::format::FormatProperties::VideoSize,
            Choice,
            Range,
            Rectangle,
            pw::spa::utils::Rectangle { width: 1920, height: 1080 },
            pw::spa::utils::Rectangle { width: 1, height: 1 },
            pw::spa::utils::Rectangle { width: 8192, height: 8192 }
        ),
        pw::spa::pod::property!(
            pw::spa::param::format::FormatProperties::VideoFramerate,
            Choice,
            Range,
            Fraction,
            pw::spa::utils::Fraction { num: 30, denom: 1 },
            pw::spa::utils::Fraction { num: 0, denom: 1 },
            pw::spa::utils::Fraction { num: 240, denom: 1 }
        ),
    );
    let values: Vec<u8> = pw::spa::pod::serialize::PodSerializer::serialize(
        std::io::Cursor::new(Vec::new()),
        &pw::spa::pod::Value::Object(obj),
    )
    .map_err(|e| anyhow!("serialize format pod: {e}"))?
    .0
    .into_inner();
    let mut params = [Pod::from_bytes(&values).ok_or_else(|| anyhow!("Pod::from_bytes"))?];

    stream
        .connect(
            spa::utils::Direction::Input,
            Some(node_id),
            pw::stream::StreamFlags::AUTOCONNECT | pw::stream::StreamFlags::MAP_BUFFERS,
            &mut params,
        )
        .context("pw stream connect")?;

    // No watchdog: pipewire-rs 0.9's MainLoopRc isn't Send, so a
    // background-thread timer that calls quit() can't compile. In
    // practice the process handler quits as soon as we've copied
    // one frame; if format negotiation never converges the caller
    // can SIGINT.
    mainloop.run();

    let captured = state.borrow().captured.clone();
    let (w, h, rgba) = captured.ok_or_else(|| anyhow!("no frame captured"))?;

    if let Some(out) = out {
        let img = image::RgbaImage::from_raw(w, h, rgba)
            .ok_or_else(|| anyhow!("frame buffer length doesn't match {}x{}", w, h))?;
        img.save(out).context("save PNG")?;
    }
    Ok((w, h))
}

/// Multi-stream variant: connect once with the shared portal FD,
/// stand up one PipeWire stream per node id, wait until every stream
/// has captured a frame, then write each as its own PNG. Stays in a
/// single mainloop tick budget — much faster than re-establishing
/// the session N times.
fn pipewire_capture_many_inner(
    fd: OwnedFd,
    node_ids: &[u32],
    outs: Option<&[&Path]>,
) -> Result<Vec<(u32, u32)>> {
    use pipewire as pw;
    use pw::spa;
    use spa::pod::Pod;
    use std::cell::RefCell;
    use std::rc::Rc;

    pw::init();
    let mainloop = pw::main_loop::MainLoopRc::new(None).context("pw main_loop")?;
    let context = pw::context::ContextRc::new(&mainloop, None).context("pw context")?;
    let core = context.connect_fd_rc(fd, None).context("pw connect_fd")?;

    #[derive(Default)]
    struct Slot {
        format: Option<spa::param::video::VideoInfoRaw>,
        captured: Option<(u32, u32, Vec<u8>)>,
    }
    let slots: Vec<Rc<RefCell<Slot>>> =
        (0..node_ids.len()).map(|_| Rc::new(RefCell::new(Slot::default()))).collect();

    // Keep the listeners alive: dropping any of them detaches the
    // callbacks before the mainloop has a chance to fire them.
    let mut listeners = Vec::new();
    let mut streams = Vec::new();

    for (idx, &node_id) in node_ids.iter().enumerate() {
        let stream = pw::stream::StreamBox::new(
            &core,
            &format!("wayland-agent-screenshot-{idx}"),
            pw::properties::properties! {
                *pw::keys::MEDIA_TYPE => "Video",
                *pw::keys::MEDIA_CATEGORY => "Capture",
                *pw::keys::MEDIA_ROLE => "Screen",
            },
        )
        .context("pw stream new")?;

        let main_q = mainloop.clone();
        let slot_p = slots[idx].clone();
        let slot_pr = slots[idx].clone();
        let slots_all = slots.clone();

        let listener = stream
            .add_local_listener_with_user_data(())
            .state_changed(move |_, _, old, new| {
                eprintln!("wayland-agent: pw stream[{idx}] {:?} -> {:?}", old, new);
            })
            .param_changed(move |_s, _ud, id, param| {
                let Some(param) = param else { return };
                if id != spa::param::ParamType::Format.as_raw() { return }
                let (mt, ms) = match spa::param::format_utils::parse_format(param) {
                    Ok(v) => v,
                    Err(_) => return,
                };
                if mt != spa::param::format::MediaType::Video
                    || ms != spa::param::format::MediaSubtype::Raw
                {
                    return;
                }
                let mut info = spa::param::video::VideoInfoRaw::default();
                if info.parse(param).is_err() { return }
                eprintln!(
                    "wayland-agent: pw stream[{idx}] format {:?} {}x{}",
                    info.format(), info.size().width, info.size().height,
                );
                slot_p.borrow_mut().format = Some(info);
            })
            .process(move |s, _ud| {
                if slot_pr.borrow().captured.is_some() { return }
                let Some(mut buffer) = s.dequeue_buffer() else { return };
                let datas = buffer.datas_mut();
                if datas.is_empty() { return }
                let Some(format) = slot_pr.borrow().format else { return };
                let chunk = datas[0].chunk();
                let size = chunk.size() as usize;
                let stride = chunk.stride() as usize;
                let pix = format.format();
                let w = format.size().width as usize;
                let h = format.size().height as usize;
                if size == 0 || bytes_per_pixel(pix) == 0 { return }
                let Some(data) = datas[0].data() else { return };
                let rgba = convert_to_rgba(data, w, h, stride, pix);
                slot_pr.borrow_mut().captured = Some((w as u32, h as u32, rgba));

                // All slots have captured? Quit the mainloop.
                if slots_all.iter().all(|s| s.borrow().captured.is_some()) {
                    main_q.quit();
                }
            })
            .register()
            .context("pw stream register")?;

        // Build the format-negotiation pod (same as single-stream).
        let obj = pw::spa::pod::object!(
            pw::spa::utils::SpaTypes::ObjectParamFormat,
            pw::spa::param::ParamType::EnumFormat,
            pw::spa::pod::property!(
                pw::spa::param::format::FormatProperties::MediaType,
                Id, pw::spa::param::format::MediaType::Video
            ),
            pw::spa::pod::property!(
                pw::spa::param::format::FormatProperties::MediaSubtype,
                Id, pw::spa::param::format::MediaSubtype::Raw
            ),
            pw::spa::pod::property!(
                pw::spa::param::format::FormatProperties::VideoFormat,
                Choice, Enum, Id,
                pw::spa::param::video::VideoFormat::BGRx,
                pw::spa::param::video::VideoFormat::BGRx,
                pw::spa::param::video::VideoFormat::RGBx,
                pw::spa::param::video::VideoFormat::RGBA,
                pw::spa::param::video::VideoFormat::BGRA,
                pw::spa::param::video::VideoFormat::RGB,
                pw::spa::param::video::VideoFormat::BGR
            ),
            pw::spa::pod::property!(
                pw::spa::param::format::FormatProperties::VideoSize,
                Choice, Range, Rectangle,
                pw::spa::utils::Rectangle { width: 1920, height: 1080 },
                pw::spa::utils::Rectangle { width: 1, height: 1 },
                pw::spa::utils::Rectangle { width: 8192, height: 8192 }
            ),
            pw::spa::pod::property!(
                pw::spa::param::format::FormatProperties::VideoFramerate,
                Choice, Range, Fraction,
                pw::spa::utils::Fraction { num: 30, denom: 1 },
                pw::spa::utils::Fraction { num: 0, denom: 1 },
                pw::spa::utils::Fraction { num: 240, denom: 1 }
            ),
        );
        let values: Vec<u8> = pw::spa::pod::serialize::PodSerializer::serialize(
            std::io::Cursor::new(Vec::new()),
            &pw::spa::pod::Value::Object(obj),
        )
        .map_err(|e| anyhow!("serialize format pod: {e}"))?
        .0
        .into_inner();
        let mut params = [Pod::from_bytes(&values).ok_or_else(|| anyhow!("Pod::from_bytes"))?];

        stream
            .connect(
                spa::utils::Direction::Input,
                Some(node_id),
                pw::stream::StreamFlags::AUTOCONNECT | pw::stream::StreamFlags::MAP_BUFFERS,
                &mut params,
            )
            .context("pw stream connect")?;

        listeners.push(listener);
        streams.push(stream);
    }

    mainloop.run();

    let mut dims = Vec::with_capacity(slots.len());
    for (idx, slot) in slots.iter().enumerate() {
        let captured = slot.borrow().captured.clone();
        let (w, h, rgba) = captured
            .ok_or_else(|| anyhow!("stream {idx}: no frame captured before quit"))?;
        if let Some(outs) = outs {
            let img = image::RgbaImage::from_raw(w, h, rgba)
                .ok_or_else(|| anyhow!("stream {idx}: bad frame buffer size"))?;
            img.save(outs[idx]).with_context(|| format!("save {}", outs[idx].display()))?;
        }
        dims.push((w, h));
    }
    Ok(dims)
}

fn bytes_per_pixel(f: pipewire::spa::param::video::VideoFormat) -> usize {
    use pipewire::spa::param::video::VideoFormat;
    match f {
        VideoFormat::BGRx | VideoFormat::RGBx | VideoFormat::BGRA | VideoFormat::RGBA => 4,
        VideoFormat::BGR | VideoFormat::RGB => 3,
        _ => 0,
    }
}

fn convert_to_rgba(
    src: &[u8],
    w: usize,
    h: usize,
    stride: usize,
    f: pipewire::spa::param::video::VideoFormat,
) -> Vec<u8> {
    use pipewire::spa::param::video::VideoFormat;
    let mut out = Vec::with_capacity(w * h * 4);
    for y in 0..h {
        let row = &src[y * stride..y * stride + w * bytes_per_pixel(f)];
        for x in 0..w {
            let bpp = bytes_per_pixel(f);
            let px = &row[x * bpp..x * bpp + bpp];
            match f {
                VideoFormat::BGRx | VideoFormat::BGRA => {
                    out.extend_from_slice(&[px[2], px[1], px[0], 0xff]);
                }
                VideoFormat::RGBx | VideoFormat::RGBA => {
                    out.extend_from_slice(&[px[0], px[1], px[2], 0xff]);
                }
                VideoFormat::BGR => {
                    out.extend_from_slice(&[px[2], px[1], px[0], 0xff]);
                }
                VideoFormat::RGB => {
                    out.extend_from_slice(&[px[0], px[1], px[2], 0xff]);
                }
                _ => unreachable!(),
            }
        }
    }
    out
}

/// Map a few common name strings to X11 keysym values. Covers what's
/// realistic for driving an emulator at a press-any-key prompt;
/// extend as needed.
pub(crate) fn keysym_from_name(name: &str) -> Option<i32> {
    let canon: String = name
        .chars()
        .enumerate()
        .map(|(i, c)| if i == 0 { c.to_ascii_uppercase() } else { c.to_ascii_lowercase() })
        .collect();
    let v = match canon.as_str() {
        "Space" | "space" => 0x0020,
        "Return" | "Enter" => 0xff0d,
        "Tab" => 0xff09,
        "Backspace" => 0xff08,
        "Escape" | "Esc" => 0xff1b,
        "Delete" => 0xffff,
        "Insert" => 0xff63,
        "Up" => 0xff52,
        "Down" => 0xff54,
        "Left" => 0xff51,
        "Right" => 0xff53,
        "Home" => 0xff50,
        "End" => 0xff57,
        "Pageup" | "Page_up" => 0xff55,
        "Pagedown" | "Page_down" => 0xff56,
        "F1" => 0xffbe,
        "F2" => 0xffbf,
        "F3" => 0xffc0,
        "F4" => 0xffc1,
        "F5" => 0xffc2,
        "F6" => 0xffc3,
        "F7" => 0xffc4,
        "F8" => 0xffc5,
        "F9" => 0xffc6,
        "F10" => 0xffc7,
        "F11" => 0xffc8,
        "F12" => 0xffc9,
        // Modifier-key keysyms.  X11 distinguishes left/right shift/
        // ctrl/alt; common shortcut notation says "Ctrl+F4" without
        // specifying which side, so the short names map to the left
        // variants.  Use Control_l / Control_r / Shift_r / Alt_r
        // explicitly if you need the right-side modifier specifically.
        "Ctrl" | "Control" | "Control_l" => 0xffe3,
        "Control_r" => 0xffe4,
        "Shift" | "Shift_l" => 0xffe1,
        "Shift_r" => 0xffe2,
        "Alt" | "Alt_l" => 0xffe9,
        "Alt_r" => 0xffea,
        "Meta" | "Meta_l" => 0xffe7,
        "Meta_r" => 0xffe8,
        "Super" | "Super_l" => 0xffeb,
        "Super_r" => 0xffec,
        _ => {
            let mut chars = name.chars();
            let first = chars.next()?;
            if chars.next().is_some() {
                return None;
            }
            return Some(first as i32);
        }
    };
    Some(v)
}

pub(crate) fn keysym_for_char(ch: char) -> Option<i32> {
    Some(match ch {
        '\n' => 0xff0d,
        '\t' => 0xff09,
        '\u{8}' => 0xff08,
        c if (c as u32) < 0x100 => c as i32,
        c if (c as u32) >= 0x100 && (c as u32) <= 0x10ffff => (c as i32) | 0x01000000,
        _ => return None,
    })
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Daemon => daemon::run_daemon().await,
        Cmd::Ping => client_call(daemon::Request::Ping).await,
        Cmd::Key { name } => client_call(daemon::Request::Key { name }).await,
        Cmd::KeyChord { keys } => client_call(daemon::Request::KeyChord { keys }).await,
        Cmd::KeyCode { code } => client_call(daemon::Request::KeyCode { code }).await,
        Cmd::KeyDown { name } => client_call(daemon::Request::KeyDown { name }).await,
        Cmd::KeyUp { name } => client_call(daemon::Request::KeyUp { name }).await,
        Cmd::Type { text } => client_call(daemon::Request::Type { text }).await,
        Cmd::Move { x, y, stream } => client_call(daemon::Request::Move { x, y, stream }).await,
        Cmd::MoveGlobal { x, y } => client_call(daemon::Request::MoveGlobal { x, y }).await,
        Cmd::Click { button } => client_call(daemon::Request::Click { button }).await,
        Cmd::ClickAt { x, y, button, stream } => {
            client_call(daemon::Request::ClickAt { x, y, button, stream }).await
        }
        Cmd::ClickGlobal { x, y, button } => {
            client_call(daemon::Request::ClickAtGlobal { x, y, button }).await
        }
        Cmd::Screenshot { out } => client_call(daemon::Request::Screenshot { out }).await,
        Cmd::Streams => client_call(daemon::Request::Streams).await,
        Cmd::StreamAt { x, y } => client_call(daemon::Request::StreamAt { x, y }).await,
        Cmd::Windows => client_call(daemon::Request::Windows).await,
        Cmd::Window { id } => client_call(daemon::Request::Window { id }).await,
        Cmd::Focus { id } => client_call(daemon::Request::FocusWindow { id }).await,
        Cmd::Monitors => client_call(daemon::Request::Monitors).await,
        Cmd::FindWindow { pattern } => client_call(daemon::Request::FindWindow { pattern }).await,
    }
}

/// Send a request to the daemon, print its response, error if the
/// daemon rejected the call.
async fn client_call(req: daemon::Request) -> Result<()> {
    let resp = daemon::client_send(&req).await?;
    match resp {
        daemon::Response::Ok { detail, paths } => {
            if let Some(d) = detail {
                println!("{d}");
            }
            if let Some(ps) = paths {
                for p in ps {
                    println!("wrote {}", p.display());
                }
            }
            Ok(())
        }
        daemon::Response::Err { error } => Err(anyhow!("{error}")),
    }
}
