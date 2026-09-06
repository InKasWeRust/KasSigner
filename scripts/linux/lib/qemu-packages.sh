# Install host packages required by Rust, espflash, and Espressif QEMU.

debian_package_installed() {
    local package="$1"
    local installed

    if dpkg-query -W -f='${Status}' "${package}" 2>/dev/null \
        | grep -q 'install ok installed'; then
        return 0
    fi

    # Debian 13 and Devuan Excalibur may replace ABI-sensitive libraries with
    # t64 packages while retaining the legacy dependency as a virtual alias.
    installed="$(dpkg-query -W -f='${binary:Package}\n' 2>/dev/null || true)"
    grep -Eq "^${package}t64(:[^[:space:]]+)?$" <<<"${installed}"
}

missing_debian_packages() {
    local package
    for package in "$@"; do
        debian_package_installed "${package}" || printf '%s\n' "${package}"
    done
}

missing_rpm_packages() {
    local package
    for package in "$@"; do
        rpm -q "${package}" >/dev/null 2>&1 || printf '%s\n' "${package}"
    done
}

missing_arch_packages() {
    local package
    for package in "$@"; do
        pacman -Q "${package}" >/dev/null 2>&1 || printf '%s\n' "${package}"
    done
}

package_reason() {
    local manager="$1"
    shift
    local joined
    joined="$(printf '%s, ' "$@")"
    joined="${joined%, }"
    printf 'Install missing %s packages required to build and run ESP32-S3 QEMU: %s.' \
        "${manager}" "${joined}"
}

install_qemu_host_packages() {
    local -a packages missing
    local reason

    if command -v apt-get >/dev/null 2>&1; then
        packages=(
            build-essential ca-certificates curl git libgcrypt20 libglib2.0-0
            libpixman-1-0 libsdl2-2.0-0 libslirp0 libudev-dev
            pkg-config python3 python3-venv unzip xz-utils
        )
        mapfile -t missing < <(missing_debian_packages "${packages[@]}")
        ((${#missing[@]} == 0)) || {
            reason="$(package_reason "Debian/Devuan" "${missing[@]}")"
            run_as_root "${reason}" apt-get update
            run_as_root "${reason}" apt-get install -y "${missing[@]}"
        }
        return
    fi

    if command -v dnf >/dev/null 2>&1; then
        packages=(
            ca-certificates curl gcc gcc-c++ git glib2 libgcrypt
            libslirp make pixman pkgconf-pkg-config python3 SDL2
            systemd-devel unzip xz
        )
        mapfile -t missing < <(missing_rpm_packages "${packages[@]}")
        ((${#missing[@]} == 0)) || {
            reason="$(package_reason "Fedora/RHEL" "${missing[@]}")"
            run_as_root "${reason}" dnf install -y "${missing[@]}"
        }
        return
    fi

    if command -v pacman >/dev/null 2>&1; then
        packages=(
            base-devel ca-certificates curl git glib2 libgcrypt
            libslirp pixman pkgconf python sdl2 systemd-libs unzip xz
        )
        mapfile -t missing < <(missing_arch_packages "${packages[@]}")
        ((${#missing[@]} == 0)) || {
            reason="$(package_reason "Arch Linux" "${missing[@]}")"
            run_as_root "${reason}" \
                pacman -Sy --needed --noconfirm "${missing[@]}"
        }
        return
    fi

    printf 'ERROR: unsupported package manager; expected apt-get, dnf, or pacman.\n' >&2
    return 2
}
