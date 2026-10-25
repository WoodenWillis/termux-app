#!/usr/bin/env python3
"""Print a FIDO2 key's CTAP2 info through fido-bridge, using python-fido2.

usage: fido-info [socket]   (default: $PREFIX/tmp/fido.sock)

Install the library on Termux with:
    pkg install python-cryptography && pip install fido2
"""
import os
import socket
import sys

# Python >= 3.13 on Android reports sys.platform == "android", which
# python-fido2 rejects at import time. Its Linux backend loads fine there and
# is never used here (we bring our own connection), so let it think "linux".
_platform = sys.platform
if _platform == "android":
    sys.platform = "linux"
try:
    from fido2.ctap2 import Ctap2
    from fido2.hid import CtapHidDevice
    from fido2.hid.base import CtapHidConnection, HidDescriptor
except ImportError:
    sys.exit("python-fido2 is missing: pkg install python-cryptography && pip install fido2")
finally:
    sys.platform = _platform

REPORT = 64


class BridgeConnection(CtapHidConnection):
    """A CTAPHID connection that sends 64-byte reports over the bridge socket."""

    def __init__(self, path):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(path)

    def write_packet(self, data):
        self.sock.sendall(bytes(data).ljust(REPORT, b"\0")[:REPORT])

    def read_packet(self):
        buf = b""
        while len(buf) < REPORT:
            chunk = self.sock.recv(REPORT - len(buf))
            if not chunk:
                raise OSError("fido-bridge closed the connection")
            buf += chunk
        return buf

    def close(self):
        self.sock.close()


def open_device(path):
    desc = HidDescriptor(path, 0, 0, REPORT, REPORT, "fido-bridge", None)
    return CtapHidDevice(desc, BridgeConnection(path))


def main():
    prefix = os.environ.get("PREFIX", "/data/data/com.termux/files/usr")
    path = sys.argv[1] if len(sys.argv) > 1 else prefix + "/tmp/fido.sock"
    try:
        dev = open_device(path)
    except OSError as e:
        sys.exit(f"cannot reach {path}: {e} (is fido-bridge running?)")

    info = Ctap2(dev).get_info()
    print(f"versions    {', '.join(info.versions)}")
    print(f"aaguid      {info.aaguid}")
    print(f"extensions  {', '.join(info.extensions) or '-'}")
    print("options     " + ", ".join(f"{k}={v}" for k, v in sorted(info.options.items())))
    if info.pin_uv_protocols:
        print(f"pin proto   {', '.join(map(str, info.pin_uv_protocols))}")
    if info.firmware_version:
        fw = info.firmware_version
        if fw > 0xFFFF:  # YubiKey style: major << 16 | minor << 8 | patch
            fw = f"{fw >> 16}.{fw >> 8 & 0xFF}.{fw & 0xFF}"
        print(f"firmware    {fw}")
    if info.remaining_disc_creds is not None:
        print(f"free slots  {info.remaining_disc_creds} passkeys")
    dev.close()


if __name__ == "__main__":
    main()
