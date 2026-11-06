#!/usr/bin/env python3
"""The signed bootloader (release/bootloader.bin, signed on hq) is exactly release/bootloader-unsigned.bin
(built from bootloader/) plus 0xFF padding and one signature sector holding the two keys of
neon/key-digests.hex, in that order: a board locked by it trusts exactly the firmware's keys.

    check-bootloader.py ESPSECURE   (run from the repository's top)
"""
import re, subprocess, sys

es = sys.argv[1]
u = open("release/bootloader-unsigned.bin", "rb").read()
s = open("release/bootloader.bin", "rb").read()
pad = (len(u) + 4095) // 4096 * 4096
ok = len(s) == pad + 4096 and s[:len(u)] == u and set(s[len(u):pad]) <= {0xFF} and len(s) <= 0x8000
if not ok:
    sys.exit("release/bootloader.bin is not release/bootloader-unsigned.bin signed once")
out = subprocess.run([es, "signature_info_v2", "release/bootloader.bin"], capture_output=True, text=True).stdout
blocks = re.findall(r"Signature block (\d) is valid.*?\nPublic key digest for block \1: ([0-9a-f ]+)", out)
found = [d.replace(" ", "") for _, d in blocks]
want = [l.strip() for l in open("neon/key-digests.hex") if l.strip() and not l.startswith("#")]
if found != want:
    sys.exit(f"signed by {found}, the firmware trusts {want}")
print("bootloader: signed by the project key and its backup, matches the source build")
