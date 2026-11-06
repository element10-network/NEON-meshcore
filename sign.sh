#!/bin/sh
# On hq: sign the bootloader and the firmware with the project's firmware key, and write the
# files atoms download (with their SHA-256 list). The key never leaves hq.
#
#   sign.sh <key.pem> <backup-key.pem> <unsigned dir (build.sh's out/)> <signed dir>
#
# The keys are made once (README, "The firmware key"). The bootloader is signed with both, so a
# secured radio trusts the backup key too (the key that replaces a lost or stolen one); the
# firmware with the project's key. The backup key is kept offline and brought to hq only for this.
[ $# -eq 4 ] || { echo "usage: sign.sh key.pem backup-key.pem unsigned-dir signed-dir" >&2; exit 2; }
set -eu
key=$1; backup=$2; in=$3; out=$4
[ -f "$key" ] && [ -f "$backup" ] && [ -f "$in/bootloader.bin" ] && [ -f "$in/firmware.bin" ] || { echo "a file is missing" >&2; exit 2; }
mkdir -p "$out"
espsecure.py sign_data --version 2 --keyfile "$key" "$backup" --output "$out/bootloader.bin" "$in/bootloader.bin"
espsecure.py sign_data --version 2 --keyfile "$key" --output "$out/firmware.bin" "$in/firmware.bin"
cp "$in/partitions.bin" "$in/boot_app0.bin" "$out/"
# The signed bootloader ends before the partition table at 0x8000.
[ "$(wc -c < "$out/bootloader.bin")" -le 32768 ] || { echo "signed bootloader too large" >&2; exit 1; }
espsecure.py verify_signature --version 2 --keyfile "$key" "$out/bootloader.bin" | grep -q "verification successful"
espsecure.py verify_signature --version 2 --keyfile "$key" "$out/firmware.bin" | grep -q "verification successful"
espsecure.py verify_signature --version 2 --keyfile "$backup" "$out/bootloader.bin" | grep -q "verification successful"
espsecure.py digest_sbv2_public_key --keyfile "$key" --output "$out/key-digest.bin" >/dev/null
# Flash layout (esptool write_flash): offset file.
printf '0x0 bootloader.bin\n0x8000 partitions.bin\n0xe000 boot_app0.bin\n0x10000 firmware.bin\n' > "$out/layout.txt"
(cd "$out" && sha256sum bootloader.bin partitions.bin boot_app0.bin firmware.bin key-digest.bin layout.txt > SHA256SUMS)
echo "signed: $out"
