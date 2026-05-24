const Animation = @This();

const std = @import("std");
const posix = std.posix;
const log = std.log;

const wayland = @import("wayland");
const wl = wayland.client.wl;

fd: posix.fd_t,
width: u32,
height: u32,
/// Milliseconds between frames.
frame_interval_ms: u64,
frame_size: usize,

shm_pool: *wl.ShmPool,
shm_data: []align(std.heap.page_size_min) u8,
buffers: [2]Buffer,
/// Index of the buffer we write into next.
back: u1 = 0,
/// Bytes already read into the back buffer for the current partial frame.
partial_offset: usize = 0,

const Buffer = struct {
    wl_buf: *wl.Buffer,
    data: []u8,
    /// Set when attached to a surface; cleared on wl_buffer.release.
    in_use: bool = false,
};

pub fn init(shm: *wl.Shm, fd: posix.fd_t, width: u32, height: u32, fps: u32) !Animation {
    const frame_size: usize = @as(usize, width) * height * 4;
    const pool_size: usize = frame_size * 2;

    // Set non-blocking so reads in next_frame never stall the event loop.
    const fl = std.c.fcntl(fd, std.c.F.GETFL, @as(c_int, 0));
    const nonblock: c_int = @bitCast(@as(u32, @bitCast(std.c.O{ .NONBLOCK = true })));
    _ = std.c.fcntl(fd, std.c.F.SETFL, fl | nonblock);

    var name_buf: [32]u8 = undefined;
    const shm_name = std.fmt.bufPrintZ(&name_buf, "/waylock-{d}", .{std.c.getpid()}) catch unreachable;
    const shm_flags: c_int = @bitCast(@as(u32, @bitCast(std.c.O{ .ACCMODE = .RDWR, .CREAT = true, .EXCL = true })));
    const mem_fd = std.c.shm_open(shm_name, shm_flags, 0o600);
    if (mem_fd < 0) return error.SystemResources;
    defer _ = std.c.close(mem_fd);
    defer _ = std.c.shm_unlink(shm_name);
    if (std.c.ftruncate(@intCast(mem_fd), @intCast(pool_size)) < 0) return error.SystemResources;

    const shm_data = try posix.mmap(
        null,
        pool_size,
        .{ .READ = true, .WRITE = true },
        .{ .TYPE = .SHARED },
        mem_fd,
        0,
    );
    errdefer posix.munmap(shm_data);

    const pool = try shm.createPool(mem_fd, @intCast(pool_size));
    errdefer pool.destroy();

    const b0 = try pool.createBuffer(0, @intCast(width), @intCast(height), @intCast(width * 4), .xrgb8888);
    errdefer b0.destroy();

    const b1 = try pool.createBuffer(@intCast(frame_size), @intCast(width), @intCast(height), @intCast(width * 4), .xrgb8888);
    errdefer b1.destroy();

    return .{
        .fd = fd,
        .width = width,
        .height = height,
        .frame_interval_ms = if (fps > 0) 1000 / @as(u64, fps) else 33,
        .frame_size = frame_size,
        .shm_pool = pool,
        .shm_data = shm_data,
        .buffers = .{
            .{ .wl_buf = b0, .data = shm_data[0..frame_size] },
            .{ .wl_buf = b1, .data = shm_data[frame_size..] },
        },
    };
}

/// Must be called once Animation is at its final memory address (i.e. stored in Lock).
pub fn init_listeners(anim: *Animation) void {
    anim.buffers[0].wl_buf.setListener(*Buffer, buffer_listener, &anim.buffers[0]);
    anim.buffers[1].wl_buf.setListener(*Buffer, buffer_listener, &anim.buffers[1]);
}

fn buffer_listener(_: *wl.Buffer, event: wl.Buffer.Event, buf: *Buffer) void {
    switch (event) {
        .release => buf.in_use = false,
    }
}

/// Read one frame from the fd into the back buffer, apply the color overlay,
/// then return the buffer to attach to surfaces. Returns null if the back
/// buffer is still held by the compositor or the frame is not yet complete.
pub fn next_frame(anim: *Animation, overlay_color: u24, overlay_alpha: u8) !?*wl.Buffer {
    const back = &anim.buffers[anim.back];
    if (back.in_use) return null;

    const done = read_partial(anim.fd, back.data, &anim.partial_offset) catch |err| switch (err) {
        error.WouldBlock => return null,
        else => return err,
    };
    if (!done) return null;

    blend(back.data, overlay_color, overlay_alpha);

    back.in_use = true;
    const result = back.wl_buf;
    anim.back ^= 1;
    return result;
}

pub fn deinit(anim: *Animation) void {
    for (&anim.buffers) |*buf| buf.wl_buf.destroy();
    anim.shm_pool.destroy();
    posix.munmap(anim.shm_data);
    _ = std.c.close(anim.fd);
}

/// Read into buf starting at *offset, advancing it as bytes arrive.
/// Returns true when a full frame is complete (offset wraps to 0).
/// Returns false when the pipe is temporarily empty (WouldBlock).
/// Progress is preserved across calls so large frames spanning multiple
/// pipe-buffer fills (e.g. raw 1080p BGRA ~8 MB) are handled correctly.
fn read_partial(fd: posix.fd_t, buf: []u8, offset: *usize) !bool {
    while (offset.* < buf.len) {
        const n = posix.read(fd, buf[offset.*..]) catch |err| switch (err) {
            error.WouldBlock => return false,
            else => return err,
        };
        if (n == 0) return error.EndOfStream;
        offset.* += n;
    }
    offset.* = 0;
    return true;
}

/// Alpha-blend a solid color over the frame in-place.
/// Data layout: B G R X per pixel (xrgb8888 / ffmpeg bgra).
fn blend(data: []u8, color: u24, alpha: u8) void {
    if (alpha == 0) return;
    const ov_b: u32 = color & 0xff;
    const ov_g: u32 = (color >> 8) & 0xff;
    const ov_r: u32 = (color >> 16) & 0xff;
    const a: u32 = alpha;
    const ia: u32 = 255 - a;
    const ov_ba = ov_b * a;
    const ov_ga = ov_g * a;
    const ov_ra = ov_r * a;
    var i: usize = 0;
    while (i < data.len) : (i += 4) {
        data[i + 0] = @intCast((data[i + 0] * ia + ov_ba) >> 8);
        data[i + 1] = @intCast((data[i + 1] * ia + ov_ga) >> 8);
        data[i + 2] = @intCast((data[i + 2] * ia + ov_ra) >> 8);
    }
}
