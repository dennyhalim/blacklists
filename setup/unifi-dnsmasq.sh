#!/bin/bash
set -euo pipefail

INSTALL_DIR="/data/domain-blocklist"
CONFIG="$INSTALL_DIR/config"
UPDATE="$INSTALL_DIR/update.sh"
CACHE="$INSTALL_DIR/blocklist.conf"
LIVE_NAME="zzz-domain-blocklist.conf"

DEFAULT_URLS=(
  "https://blacklists.pages.dev/dist/dnsmasq/threat.conf"
  "https://blacklists.pages.dev/dist/dnsmasq/gambling.conf"
  "https://blacklists.pages.dev/dist/dnsmasq/nsfw.conf"
)

SERVICE="/etc/systemd/system/domain-blocklist.service"
TIMER="/etc/systemd/system/domain-blocklist.timer"

[[ $EUID -eq 0 ]] || { echo "ERROR: run as root." >&2; exit 1; }

for cmd in curl grep install systemctl ps; do
  command -v "$cmd" >/dev/null || { echo "ERROR: missing: $cmd" >&2; exit 1; }
done

mkdir -p "$INSTALL_DIR"
URLS=("$@")
((${#URLS[@]})) || URLS=("${DEFAULT_URLS[@]}")

{
  echo 'URLS=('
  for url in "${URLS[@]}"; do printf '  %q\n' "$url"; done
  echo ')'
} >"$CONFIG"

cat >"$UPDATE" <<'EOF'
#!/bin/bash
set -euo pipefail

INSTALL_DIR="/data/domain-blocklist"
source "$INSTALL_DIR/config"
CACHE="$INSTALL_DIR/blocklist.conf"
LIVE_NAME="zzz-domain-blocklist.conf"

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
: >"$tmp"

for url in "${URLS[@]}"; do
  echo "Downloading: $url"
  curl -fsSL "$url" >>"$tmp"
  printf '\n' >>"$tmp"
done

[[ -s "$tmp" ]] || { echo "ERROR: downloaded blocklist is empty." >&2; exit 1; }

args="$(ps -eo args | grep '[d]nsmasq' | head -n1 || true)"
conf_dir="$(grep -oE -- '--conf-dir=([^ ,]+)' <<<"$args" | head -n1 | cut -d= -f2- || true)"

[[ -n "$conf_dir" ]] || { echo "ERROR: dnsmasq --conf-dir not found." >&2; exit 1; }
[[ -d "$conf_dir" ]] || { echo "ERROR: dnsmasq conf-dir missing: $conf_dir" >&2; exit 1; }

if command -v dnsmasq >/dev/null; then
  dnsmasq --test --conf-file="$tmp" >/dev/null 2>&1 ||
    { echo "ERROR: dnsmasq validation failed." >&2; exit 1; }
fi

install -m 0644 "$tmp" "$CACHE"
install -m 0644 "$CACHE" "$conf_dir/.${LIVE_NAME}.tmp"
mv -f "$conf_dir/.${LIVE_NAME}.tmp" "$conf_dir/$LIVE_NAME"

if systemctl reload dnsmasq 2>/dev/null; then
  :
elif systemctl restart dnsmasq 2>/dev/null; then
  :
else
  pid="$(pgrep -x dnsmasq | head -n1 || true)"
  [[ -n "$pid" ]] || { echo "ERROR: cannot reload dnsmasq." >&2; exit 1; }
  kill -HUP "$pid"
fi

echo "OK: installed $conf_dir/$LIVE_NAME"
EOF
chmod 0755 "$UPDATE"

cat >"$SERVICE" <<EOF
[Unit]
Description=Update UniFi domain blocklist
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart=$UPDATE
EOF

cat >"$TIMER" <<'EOF'
[Unit]
Description=Periodic UniFi domain blocklist update

[Timer]
OnBootSec=2min
OnUnitActiveSec=30min
Persistent=true

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now domain-blocklist.timer
"$UPDATE"

echo "Installed. Default: ${DEFAULT_URLS[0]}"
