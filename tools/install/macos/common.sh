cd ~

# ── Colors ──
G='\033[0;32m'
R='\033[0;31m'
C='\033[0;36m'
Y='\033[1;33m'
B='\033[1m'
D='\033[2m'
X='\033[0m'

SECONDS=0

# ── Helpers ──
ask() {
    echo ""
    echo -e "  ${B}$1${X}"
    echo -e "  ${D}$2${X}"
    echo ""
    while true; do
        read -p "  Ready? [Y/N]: " yn </dev/tty
        case $yn in
            [Yy]* ) echo ""; return 0;;
            [Nn]* ) echo -e "\n  ${Y}Skipped.${X}\n"; return 1;;
            * ) echo "  Type Y or N and press Enter.";;
        esac
    done
}

ok()   { echo -e "  ${G}✓${X} $1"; }
warn() { echo -e "  ${Y}⚠${X} $1"; }
bad()  { echo -e "  ${R}✗${X} $1"; }
note() { echo -e "  ${C}→${X} $1"; }

die() {
    echo ""
    echo -e "  ${R}${B}$1${X}"
    [ -n "${2:-}" ] && echo -e "  ${D}${2}${X}"
    echo ""
    exit 1
}

# ── Banner ──
clear
echo ""
echo ""
echo -e "  ${B}┌──────────────────────────────────────────┐${X}"
echo -e "  ${B}│                                          │${X}"
echo -e "  ${B}│        KasSigner Installer                │${X}"
echo -e "  ${B}│                                          │${X}"
echo -e "  ${B}│   Sets up your environment if needed,     │${X}"
echo -e "  ${B}│   then builds and flashes firmware.       │${X}"
echo -e "  ${B}│                                          │${X}"
echo -e "  ${B}│   Just answer Y or N at each step.        │${X}"
echo -e "  ${B}│                                          │${X}"
echo -e "  ${B}└──────────────────────────────────────────┘${X}"
echo ""
