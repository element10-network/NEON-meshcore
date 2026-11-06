#!/bin/sh
# On hq: sign the bootloader and the firmware with the project's firmware key, and write the
# files atoms download (with their SHA-256 list). The key never leaves hq.
#
#   sign.sh <key.pem> <unsigned dir (build.sh's out/)> <signed dir>
#
# The key is made once (README, "The firmware key"); every secured radio checks this key's digest
# for good, so a lost key means no more updates for those radios.
set -eu
key=$1; in=$2; out=$3
[ -f "$key" ] && [ -f "$in/bootloader.bin" ] && [ -f "$in/firmware.bin" ] || { echo "usage: sign.sh key.pem unsigned-dir signed-dir" >&2; exit 2; }
mkdir -p "$out"
espsecure.py sign_data --version 2 --keyfile "$key" --output "$out/bootloader.bin" "$in/bootloader.bin"
espsecure.py sign_data --version 2 --keyfile "$key" --output "$out/firmware.bin" "$in/firmware.bin"
cp "$in/partitions.bin" "$in/boot_app0.bin" "$out/"
# Signed bootloader: at most 0x7000 bytes (it ends before the partition table at 0x8000).
[ "$(wc -c < "$out/bootloader.bin")" -le 28672 ] || { echo "signed bootloader too large" >&2; exit 1; }
espsecure.py verify_signature --version 2 --keyfile "$key" "$out/bootloader.bin" | grep -q "verification successful"
espsecure.py verify_signature --version 2 --keyfile "$key" "$out/firmware.bin" | grep -q "verification successful"
espsecure.py digest_sbv2_public_key --keyfile "$key" --output "$out/key-digest.bin" >/dev/null
# Flash layout (esptool write_flash): offset file.
printf '0x0 bootloader.bin\n0x8000 partitions.bin\n0xe000 boot_app0.bin\n0x10000 firmware.bin\n' > "$out/layout.txt"
(cd "$out" && sha256sum bootloader.bin partitions.bin boot_app0.bin firmware.bin key-digest.bin layout.txt > SHA256SUMS)
echo "signed: $out"
