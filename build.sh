#!/bin/sh
# Builds Neon's MeshCore radio firmware for the Heltec V3: MeshCore at the pinned commit
# (MESHCORE_COMMIT), Neon's hooks (neon/companion_radio.patch) and code (neon/*.cpp, *.h).
# The result is unsigned: sign.sh signs it on hq with the project's firmware key.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
commit=$(cat "$here/MESHCORE_COMMIT")
work="$here/build/MeshCore"
if [ ! -d "$work/.git" ]; then
    mkdir -p "$here/build"
    git init -q "$work"
    git -C "$work" remote add origin https://github.com/meshcore-dev/MeshCore.git
fi
git -C "$work" fetch -q --depth 1 origin "$commit"
git -C "$work" checkout -q -f "$commit"
git -C "$work" clean -qfd -e .pio
git -C "$work" apply "$here/neon/companion_radio.patch"
mkdir -p "$work/src/helpers/neon"
cp "$here"/neon/*.cpp "$here"/neon/*.h "$work/src/helpers/neon/"
cp "$here/platformio.local.ini" "$work/platformio.local.ini"
export PLATFORMIO_SETTING_ENABLE_TELEMETRY=No
(cd "$work" && pio run -e neon_heltec_v3)
# The bootloader with secure boot (bootloader/), unsigned too.
(cd "$here/bootloader" && pio run)
mkdir -p "$here/out"
b="$work/.pio/build/neon_heltec_v3"
cp "$b/firmware.bin" "$here/out/firmware.bin"
cp "$b/partitions.bin" "$here/out/partitions.bin"
cp "$HOME/.platformio/packages/framework-arduinoespressif32/tools/partitions/boot_app0.bin" "$here/out/boot_app0.bin"
cp "$here/bootloader/.pio/build/bootloader/bootloader.bin" "$here/out/bootloader.bin"
# A signed bootloader must end before the partition table (0x8000) with its 4 KiB signature.
size=$(wc -c < "$here/out/bootloader.bin")
[ $(( (size + 4095) / 4096 * 4096 + 4096 )) -le 32768 ] || { echo "bootloader too large to sign: $size bytes" >&2; exit 1; }
echo "built (unsigned) in out/: bootloader.bin partitions.bin boot_app0.bin firmware.bin"
