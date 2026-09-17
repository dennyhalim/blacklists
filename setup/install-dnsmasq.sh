#!/bin/bash
# bl.dennyhalim.com
set -euo pipefail

DEFAULT_URLS=(
  "https://blacklists.pages.dev/dist/dnsmasq/threat.conf"
  "https://blacklists.pages.dev/dist/dnsmasq/gambling.conf"
  "https://blacklists.pages.dev/dist/dnsmasq/nsfw.conf"
)

LIVE_NAME="zzz-domain-blocklist.conf"
SERVICE_NAME="domain-blocklist.service"
TIMER_NAME="domain-blocklist.timer"
SERVICE="/etc/systemd/system/$SERVICE_NAME"
TIMER="/etc/systemd/system/$TIMER_NAME"

[[ $EUID -eq 0 ]] || { echo "ERROR: run as root." >&2; exit 1; }

for cmd in curl grep install systemctl ps; do
  command -v "$cmd" >/dev/null || { echo "ERROR: missing command: $cmd" >&2; exit 1; }
done

# UniFi keeps persistent custom data under /data. Normal Linux uses /var/lib.
if [[ -d /data ]] && ps -eo args | grep -q '[d]nsmasq'; then
  INSTALL_DIR="/data/domain-blocklist"
else
  INSTALL_DIR="/var/lib/domain-blocklist"
fi

CONFIG="$INSTALL_DIR/config"
UPDATE="$INSTALL_DIR/update.sh"
CACHE="$INSTALL_DIR/blocklist.conf"

mkdir -p "$INSTALL_DIR"

URLS=("$@")
((${#URLS[@]})) || URLS=("${DEFAULT_URLS[@]}")

{
  echo 'URLS=('
  for url in "${URLS[@]}"; do
    printf '  %q\n' "$url"
  done
  echo ')'
} >"$CONFIG"

cat >"$UPDATE" <<EOF
#!/bin/bash
set -euo pipefail

INSTALL_DIR=$(printf '%q' "$INSTALL_DIR")
CONFIG="\$INSTALL_DIR/config"
CACHE="\$INSTALL_DIR/blocklist.conf"
LIVE_NAME=$(printf '%q' "$LIVE_NAME")

source "\$CONFIG"

tmp="\$(mktemp)"
trap 'rm -f "\$tmp"' EXIT
: >"\$tmp"

for url in "\${URLS[@]}"; do
  echo "Downloading: \$url"
  curl -fsSL "\$url" >>"\$tmp"
  printf '\\n' >>"\$tmp"
done

[[ -s "\$tmp" ]] || {
  echo "ERROR: downloaded blocklist is empty." >&2
  exit 1
}

detect_conf_dir() {
  local args dir

  # Prefer the conf-dir of the actual running dnsmasq. This covers UniFi and
  # Linux installations using a nonstandard include directory.
  args="\$(ps -eo args 2>/dev/null | grep '[d]nsmasq' | head -n1 || true)"
  if [[ -n "\$args" ]]; then
    dir="\$(grep -oE -- '--conf-dir=([^ ,]+)' <<<"\$args" | head -n1 | cut -d= -f2- || true)"
    if [[ -n "\$dir" && -d "\$dir" ]]; then
      printf '%s\\n' "\$dir"
      return
    fi
  fi

  # Standard Linux fallback.
  if [[ -d /etc/dnsmasq.d ]]; then
    printf '%s\\n' /etc/dnsmasq.d
    return
  fi

  return 1
}

CONF_DIR="\$(detect_conf_dir)" || {
  echo "ERROR: cannot find a dnsmasq conf-dir." >&2
  exit 1
}

# Validate the downloaded dnsmasq configuration before replacing anything.
if command -v dnsmasq >/dev/null 2>&1; then
  dnsmasq --test --conf-file="\$tmp" >/dev/null 2>&1 || {
    echo "ERROR: downloaded dnsmasq configuration failed validation." >&2
    exit 1
  }
fi

install -m 0644 "\$tmp" "\$CACHE"

live="\$CONF_DIR/\$LIVE_NAME"
live_tmp="\$CONF_DIR/.\$LIVE_NAME.tmp"
install -m 0644 "\$CACHE" "\$live_tmp"
mv -f "\$live_tmp" "\$live"

# Try the normal service interfaces first, then signal the daemon directly.
if systemctl reload dnsmasq 2>/dev/null; then
  :
elif systemctl restart dnsmasq 2>/dev/null; then
  :
else
  pid="\$(pgrep -x dnsmasq | head -n1 || true)"
  [[ -n "\$pid" ]] || {
    echo "ERROR: blocklist installed but dnsmasq could not be reloaded." >&2
    exit 1
  }
  kill -HUP "\$pid"
fi

echo "OK: installed \$live"
EOF

chmod 0755 "$UPDATE"

cat >"$SERVICE" <<EOF
[Unit]
Description=Update dnsmasq domain blocklist
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart=$UPDATE
EOF

cat >"$TIMER" <<'EOF'
[Unit]
Description=Periodic dnsmasq domain blocklist update

[Timer]
OnBootSec=2min
OnUnitActiveSec=30min
Persistent=true

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now "$TIMER_NAME"

echo "Running initial update..."
"$UPDATE"

echo
echo "Installed."
echo "Data:    $INSTALL_DIR"
echo "Updater: $UPDATE"
echo "Timer:   $TIMER_NAME"
echo "Default: ${DEFAULT_URLS[0]}"
