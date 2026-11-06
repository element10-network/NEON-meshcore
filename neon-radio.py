#!/usr/bin/env python3
"""The secured radio's Neon commands over USB, with neond stopped (it holds the port).

    neon-radio.py [--port /dev/ttyUSB0] identity
    neon-radio.py [--port ...] provision          # once in the chip's life; takes minutes
    neon-radio.py [--port ...] backup DIR         # the key's parameters (useless off this chip) and public key
    neon-radio.py [--port ...] restore DIR        # after the radio's flash was wiped

Runs with the esptool venv's Python (pyserial): /root/esptool/bin/python neon-radio.py ...
The port is opened with DTR and RTS both asserted, which neither resets the board nor selects
download mode on the Heltec V3's auto-reset circuit.
"""
import argparse, hashlib, os, struct, sys, time
import serial

CMD_NEON = 0xE0
SUB_IDENTITY, SUB_PROVISION, SUB_PUBKEY, SUB_NONCE, SUB_BLOB_GET, SUB_BLOB_PUT, SUB_BLOB_COMMIT = 1, 2, 3, 4, 5, 6, 7
RESP = {0xE1: "identity", 0xE2: "pubkey", 0xE3: "blob", 0xEF: "error"}
BITS = [(1, "secure boot on"), (2, "JTAG off"), (4, "secure download mode"), (8, "key ready"),
        (16, "only Neon's keys trusted"), (32, "KEY PARAMETERS MISSING (restore from backup)")]
READY_TO_PROVISION = 1 | 2 | 4 | 16


def open_port(port):
    s = serial.Serial()
    s.port, s.baudrate, s.timeout = port, 115200, 0.5
    s.dtr, s.rts = True, True
    s.open()
    time.sleep(0.3)
    s.reset_input_buffer()
    return s


def ask(s, payload, timeout=10.0):
    s.write(b"<" + struct.pack("<H", len(payload)) + bytes(payload))
    end, buf = time.time() + timeout, b""
    while time.time() < end:
        buf += s.read(512)
        while True:
            i = buf.find(b">")
            if i < 0 or len(buf) < i + 3:
                break
            n = struct.unpack("<H", buf[i + 1:i + 3])[0]
            if len(buf) < i + 3 + n:
                break
            frame, buf = buf[i + 3:i + 3 + n], buf[i + 3 + n:]
            if frame and frame[0] in RESP:
                if frame[0] == 0xEF:
                    sys.exit(f"radio refused (code {frame[1]}): {frame[2:].decode(errors='replace')}")
                return frame
    sys.exit("no answer from the radio (is neond stopped? is this the Neon firmware?)")


def identity(s, show=True):
    f = ask(s, [CMD_NEON, SUB_IDENTITY])
    st = f[2]
    if show:
        print(f"status 0x{st:02x}: " + (", ".join(t for b, t in BITS if st & b) or "nothing locked yet"))
        print("mac", f[3:9].hex(":"), "boot", struct.unpack("<I", f[9:13])[0])
        if st & 8:
            print("key block", f[13], "public key sha256", f[14:46].hex())
    return st


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", default="/dev/ttyUSB0")
    ap.add_argument("cmd", choices=["identity", "provision", "backup", "restore"])
    ap.add_argument("dir", nargs="?")
    a = ap.parse_args()
    s = open_port(a.port)
    st = identity(s, show=a.cmd == "identity")
    if a.cmd == "provision":
        if st & 8:
            sys.exit("already provisioned")
        if st & 32:
            sys.exit("this chip has a key whose parameters are missing: use restore, never provision")
        if st & READY_TO_PROVISION != READY_TO_PROVISION:
            identity(s)
            sys.exit("not ready: provisioning needs status 0x17 (secure boot, JTAG off, secure download, only Neon's keys)")
        print("provisioning: making the key takes minutes; do not unplug or touch the port ...")
        f = ask(s, [CMD_NEON, SUB_PROVISION], timeout=900)
        print("done: status 0x%02x; the radio restarts in 3 s. Now run: backup DIR" % f[2])
    elif a.cmd == "backup":
        if not a.dir or not st & 8:
            sys.exit("usage: backup DIR (on a provisioned radio)")
        os.makedirs(a.dir, exist_ok=True)
        blob, parts, part = b"", 1, 0
        while part < parts:
            f = ask(s, [CMD_NEON, SUB_BLOB_GET, part])
            parts, blob, part = f[2], blob + f[3:], part + 1
        mod = b"".join(ask(s, [CMD_NEON, SUB_PUBKEY, k])[2:] for k in range(3))
        open(os.path.join(a.dir, "ds-params.bin"), "wb").write(blob)
        open(os.path.join(a.dir, "public-key-modulus.bin"), "wb").write(mod)
        print(f"saved {len(blob)} bytes of parameters and the public key to {a.dir} "
              f"(sha256 of the public key {hashlib.sha256(mod).hexdigest()}); copy them to hq too")
    elif a.cmd == "restore":
        if not a.dir:
            sys.exit("usage: restore DIR")
        blob = open(os.path.join(a.dir, "ds-params.bin"), "rb").read()
        for part in range((len(blob) + 127) // 128):
            ask(s, [CMD_NEON, SUB_BLOB_PUT, part] + list(blob[part * 128:(part + 1) * 128]))
        f = ask(s, [CMD_NEON, SUB_BLOB_COMMIT])
        print("restored: status 0x%02x" % f[2])
    s.close()


if __name__ == "__main__":
    main()
