#!/bin/sh
# Lantern Installer & Updater
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/DhyaanKanoja11/Lantern/main/install.sh | bash
# Options via environment variables:
#   LANTERN_VERSION=v0.1.2  # Specify exact version (default: latest)
#   INSTALL_DIR=/usr/local/bin  # Override installation directory
#
# To uninstall:
#   curl -fsSL https://raw.githubusercontent.com/DhyaanKanoja11/Lantern/main/install.sh | bash -s -- --uninstall

set -eu

REPO="DhyaanKanoja11/Lantern"
FALLBACK_VERSION="v0.2.0"

# Colors for terminal output
BOLD="\033[1m"
GREEN="\033[32m"
YELLOW="\033[33m"
RED="\033[31m"
RESET="\033[0m"

log_info() {
    printf "${BOLD}==>${RESET} %s\n" "$1"
}

log_success() {
    printf "${GREEN}${BOLD}==>${RESET} %s\n" "$1"
}

log_warn() {
    printf "${YELLOW}${BOLD}Warning:${RESET} %s\n" "$1"
}

log_error() {
    printf "${RED}${BOLD}Error:${RESET} %s\n" "$1" >&2
}

# Check for uninstall flag
if [ "${1:-}" = "--uninstall" ]; then
    log_info "Uninstalling Lantern..."
    TARGETS="/usr/local/bin/lantern $HOME/.local/bin/lantern"
    FOUND=0
    for t in $TARGETS; do
        if [ -f "$t" ]; then
            if [ -w "$t" ]; then
                rm -f "$t"
                log_success "Removed $t"
            elif command -v sudo >/dev/null 2>&1; then
                sudo rm -f "$t"
                log_success "Removed $t (using sudo)"
            else
                log_error "Permission denied to remove $t. Run with appropriate privileges."
                exit 1
            fi
            FOUND=1
        fi
    done
    if [ "$FOUND" -eq 0 ]; then
        log_info "Lantern was not found in standard installation paths ($TARGETS)."
    else
        log_success "Lantern successfully uninstalled."
    fi
    exit 0
fi

# Detect Operating System
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "$OS" in
    linux)  OS="linux" ;;
    darwin) OS="darwin" ;;
    *)
        log_error "Unsupported operating system: $OS"
        log_warn "Lantern requires Linux or WSL2 for native socket inspection. Windows/macOS support is diagnostic-only."
        exit 1
        ;;
esac

# Detect Architecture
ARCH="$(uname -m)"
case "$ARCH" in
    x86_64|amd64)   ARCH="amd64" ;;
    aarch64|arm64)  ARCH="arm64" ;;
    *)
        log_error "Unsupported architecture: $ARCH (Lantern releases support amd64 and arm64)"
        exit 1
        ;;
esac

# Determine Version to Install
VERSION="${LANTERN_VERSION:-}"
if [ -z "$VERSION" ]; then
    log_info "Resolving latest Lantern release..."
    if command -v curl >/dev/null 2>&1; then
        LATEST_TAG=$(curl -fsSL -H "Accept: application/vnd.github.v3+json" "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/' || true)
    elif command -v wget >/dev/null 2>&1; then
        LATEST_TAG=$(wget -qO- --header="Accept: application/vnd.github.v3+json" "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/' || true)
    else
        log_error "curl or wget is required to run this installer."
        exit 1
    fi

    if [ -n "$LATEST_TAG" ]; then
        VERSION="$LATEST_TAG"
    else
        log_warn "Could not resolve latest release via GitHub API (rate limit or offline); falling back to $FALLBACK_VERSION"
        VERSION="$FALLBACK_VERSION"
    fi
fi

# Strip leading 'v' for archive naming if present
CLEAN_VER="${VERSION#v}"
ARCHIVE_NAME="lantern_${CLEAN_VER}_${OS}_${ARCH}.tar.gz"
DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/${ARCHIVE_NAME}"
CHECKSUMS_URL="https://github.com/${REPO}/releases/download/${VERSION}/checksums.txt"

# Temporary directory with cleanup trap
TMP_DIR="$(mktemp -d 2>/dev/null || mktemp -d -t 'lantern-install')"
trap 'rm -rf "$TMP_DIR"' EXIT INT TERM

log_info "Downloading Lantern ${VERSION} (${OS}/${ARCH})..."
if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$DOWNLOAD_URL" -o "$TMP_DIR/$ARCHIVE_NAME" || {
        log_error "Failed to download $DOWNLOAD_URL"
        exit 1
    }
    curl -fsSL "$CHECKSUMS_URL" -o "$TMP_DIR/checksums.txt" || {
        log_warn "Checksums file not available; proceeding with download verification via archive integrity"
    }
elif command -v wget >/dev/null 2>&1; then
    wget -qO "$TMP_DIR/$ARCHIVE_NAME" "$DOWNLOAD_URL" || {
        log_error "Failed to download $DOWNLOAD_URL"
        exit 1
    }
    wget -qO "$TMP_DIR/checksums.txt" "$CHECKSUMS_URL" || {
        log_warn "Checksums file not available; proceeding with download verification via archive integrity"
    }
fi

# Verify SHA-256 Checksum if checksums.txt is available
if [ -f "$TMP_DIR/checksums.txt" ]; then
    log_info "Verifying SHA-256 checksum..."
    EXPECTED_SHA=$(grep "$ARCHIVE_NAME" "$TMP_DIR/checksums.txt" | awk '{print $1}')
    if [ -n "$EXPECTED_SHA" ]; then
        if command -v sha256sum >/dev/null 2>&1; then
            ACTUAL_SHA=$(sha256sum "$TMP_DIR/$ARCHIVE_NAME" | awk '{print $1}')
        elif command -v shasum >/dev/null 2>&1; then
            ACTUAL_SHA=$(shasum -a 256 "$TMP_DIR/$ARCHIVE_NAME" | awk '{print $1}')
        else
            ACTUAL_SHA=""
            log_warn "Neither sha256sum nor shasum is available; skipping cryptographic hash check"
        fi

        if [ -n "$ACTUAL_SHA" ]; then
            if [ "$EXPECTED_SHA" != "$ACTUAL_SHA" ]; then
                log_error "Checksum verification FAILED!"
                log_error "Expected: $EXPECTED_SHA"
                log_error "Actual:   $ACTUAL_SHA"
                exit 1
            fi
            log_success "Checksum verified: ${ACTUAL_SHA}"
        fi
    fi
fi

# Extract binary
log_info "Extracting archive..."
tar -xzf "$TMP_DIR/$ARCHIVE_NAME" -C "$TMP_DIR"
if [ ! -f "$TMP_DIR/lantern" ]; then
    log_error "Archive did not contain the 'lantern' binary"
    exit 1
fi
chmod +x "$TMP_DIR/lantern"

# Determine Installation Directory
if [ -n "${INSTALL_DIR:-}" ]; then
    TARGET_DIR="$INSTALL_DIR"
elif [ -w "/usr/local/bin" ]; then
    TARGET_DIR="/usr/local/bin"
elif command -v sudo >/dev/null 2>&1 && [ -t 0 ]; then
    TARGET_DIR="/usr/local/bin"
else
    TARGET_DIR="$HOME/.local/bin"
fi

mkdir -p "$TARGET_DIR" 2>/dev/null || true

# Copy Binary
log_info "Installing to ${TARGET_DIR}/lantern..."
if [ -w "$TARGET_DIR" ]; then
    cp "$TMP_DIR/lantern" "$TARGET_DIR/lantern"
else
    if command -v sudo >/dev/null 2>&1; then
        sudo cp "$TMP_DIR/lantern" "$TARGET_DIR/lantern"
    else
        log_error "Target directory $TARGET_DIR is not writable and sudo is not available."
        log_info "Re-run with INSTALL_DIR=\$HOME/.local/bin or run as root."
        exit 1
    fi
fi

# Verify Installation
if [ -x "$TARGET_DIR/lantern" ]; then
    log_success "Installed Lantern at $TARGET_DIR/lantern"
else
    log_error "Failed to verify executable permissions on $TARGET_DIR/lantern"
    exit 1
fi

# Check PATH
case ":$PATH:" in
    *":$TARGET_DIR:"*) ;;
    *)
        log_warn "$TARGET_DIR is not in your current PATH."
        printf "\n"

        DETECTED_SHELL="$(basename "${SHELL:-sh}")"
        case "$DETECTED_SHELL" in
            zsh)
                printf "To use Lantern in your current terminal session:\n"
                printf "    ${BOLD}export PATH=\"%s:\$PATH\"${RESET}\n\n" "$TARGET_DIR"
                printf "To make this change persistent across new terminal sessions (Zsh):\n"
                printf "    ${BOLD}echo 'export PATH=\"%s:\$PATH\"' >> ~/.zshrc${RESET}\n" "$TARGET_DIR"
                printf "    ${BOLD}source ~/.zshrc${RESET}\n\n"
                ;;
            bash)
                printf "To use Lantern in your current terminal session:\n"
                printf "    ${BOLD}export PATH=\"%s:\$PATH\"${RESET}\n\n" "$TARGET_DIR"
                printf "To make this change persistent across new terminal sessions (Bash):\n"
                if [ "$OS" = "darwin" ]; then
                    printf "    ${BOLD}echo 'export PATH=\"%s:\$PATH\"' >> ~/.bash_profile${RESET}\n" "$TARGET_DIR"
                    printf "    ${BOLD}source ~/.bash_profile${RESET}\n\n"
                else
                    printf "    ${BOLD}echo 'export PATH=\"%s:\$PATH\"' >> ~/.bashrc${RESET}\n" "$TARGET_DIR"
                    printf "    ${BOLD}source ~/.bashrc${RESET}\n\n"
                fi
                ;;
            fish)
                printf "To add Lantern permanently to your PATH in Fish shell:\n"
                printf "    ${BOLD}fish_add_path %s${RESET}\n\n" "$TARGET_DIR"
                ;;
            *)
                printf "To use Lantern in your current terminal session:\n"
                printf "    ${BOLD}export PATH=\"%s:\$PATH\"${RESET}\n\n" "$TARGET_DIR"
                printf "To make this change persistent across new terminal sessions:\n"
                printf "    Add ${BOLD}'export PATH=\"%s:\$PATH\"'${RESET} to your shell configuration (~/.profile, ~/.bashrc, or ~/.zshrc).\n\n" "$TARGET_DIR"
                ;;
        esac

        printf "Note: Lantern does not modify your shell configuration files automatically.\n\n"
        ;;
esac

# Run diagnostic check
printf "\n"
"$TARGET_DIR/lantern" version || true
printf "\n"
log_success "Lantern is ready to use!"
printf "Run '%s doctor' to check your local environment diagnostics.\n" "lantern"
