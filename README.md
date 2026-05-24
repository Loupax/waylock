# waylock

Waylock is a small screenlocker for Wayland compositors implementing
`ext-session-lock-v1`. The `ext-session-lock-v1` protocol is significantly
more robust than previous client-side Wayland screen locking approaches.
Importantly, the screenlocker crashing does not cause the session to be
unlocked.

Install from your [package manager](https://repology.org/project/waylock/versions)

The main repository is on [codeberg](https://codeberg.org/ifreund/waylock),
which is where the issue tracker may be found and where contributions are accepted.

Read-only mirrors exist on [sourcehut](https://git.sr.ht/~ifreund/waylock)
and [github](https://github.com/ifreund/waylock).

## Building

Note: If you are packaging waylock for distribution, see [PACKAGING.md](PACKAGING.md).

To compile waylock first ensure that you have the following dependencies
installed:

- [zig](https://ziglang.org/download/) 0.16
- wayland
- wayland-protocols
- xkbcommon
- pam
- pkg-config
- scdoc (optional, but required for man page generation)

Then run, for example:

```
zig build -Doptimize=ReleaseSafe --prefix /usr install
```

Note that PAM will only use configuration files in the system directory,
likely `/etc/pam.d` by default. Therefore care must be taken if
installing to a prefix other than `/usr` to ensure the configuration file
[pam.d/waylock](pam.d/waylock) is found by PAM.

## Usage

See the `waylock(1)` man page or the output of `waylock -h` for an overview
of the command line options.

Run the waylock executable to lock the session. All monitors will be blanked
with the `-init-color`. Typing causes the color to change to the
`-input-color`. `Esc` or `Ctrl-U` clears all current input, while `backspace`
deletes the last UTF-8 codepoint.

To unlock the session, type your password and press `Enter`. If the password
is correct, waylock will unlock the session and exit. Otherwise, the color
will change to the `-fail-color` and you may try again.

In order to automatically run waylock after a certain amount of time with no
input or before sleep, the [swayidle](https://github.com/swaywm/swayidle)
utility or a similar program may be used. See the `swayidle(1)` man page
for details.

## Animation background

Waylock can display an animated background by reading raw BGRA video frames
from a file descriptor. Decoding is delegated to an external tool such as
[ffmpeg](https://ffmpeg.org/), keeping waylock free of media dependencies.

Required flags when using animation:

- `-animation-fd <fd>` — file descriptor providing raw BGRA frames
- `-animation-width <px>` — frame width in pixels
- `-animation-height <px>` — frame height in pixels

Optional flags:

- `-animation-fps <n>` — playback rate (default: 30)
- `-overlay-opacity 0xNN` — alpha of the state color tinted over each frame;
  `0x00` disables blending, `0xff` is fully opaque (default: `0x80`)

The state color overlay (init/input/fail) is only blended when you start
typing — the animation runs at full speed while the screen is idle.

### Example with ffmpeg

Use `-pix_fmt bgra` to match the expected byte layout, `-nostdin` to prevent
ffmpeg from altering the terminal state, and `-stream_loop -1` to loop:

```sh
waylock -animation-fd 3 -animation-width 1920 -animation-height 1080 \
  3< <(ffmpeg -nostdin -stream_loop -1 -i /path/to/video.mp4 \
       -an -f rawvideo -pix_fmt bgra - 2>/dev/null)
```

`-an` drops the audio track. Any format ffmpeg can decode works — mp4, mkv,
webp, gif, etc. If the stream ends, waylock falls back to the solid init color.

## Licensing

Waylock is released under the ISC License.
