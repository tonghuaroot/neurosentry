#!/usr/bin/env bash
# Convert the Playwright-recorded tour video into a high-quality GIF (two-pass
# palette) and an MP4 for the docs. Requires ffmpeg.
#   ./scripts/media-to-gif.sh
set -euo pipefail
VID="docs/media/video/guided-tour.webm"
OUT="docs/media/guided-tour"
W="${GIF_WIDTH:-1120}"
FPS="${GIF_FPS:-14}"

[ -f "$VID" ] || { echo "no video at $VID — run scripts/capture-media.mjs first"; exit 1; }
mkdir -p "$(dirname "$OUT")"
pal="$(mktemp -t nspal.XXXX).png"

ffmpeg -y -i "$VID" -vf "fps=${FPS},scale=${W}:-1:flags=lanczos,palettegen=stats_mode=diff" "$pal" -loglevel error
ffmpeg -y -i "$VID" -i "$pal" -lavfi "fps=${FPS},scale=${W}:-1:flags=lanczos[x];[x][1:v]paletteuse=dither=bayer:bayer_scale=5:diff_mode=rectangle" "${OUT}.gif" -loglevel error
ffmpeg -y -i "$VID" -movflags +faststart -pix_fmt yuv420p -vf "scale=1280:-2" "${OUT}.mp4" -loglevel error
rm -f "$pal"

echo "wrote ${OUT}.gif and ${OUT}.mp4"
ls -lh "${OUT}.gif" "${OUT}.mp4"
