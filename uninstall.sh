#!/usr/bin/env bash
set -euo pipefail

APP_DIR="/opt/homecom"
APP_USER="homecom"
SERVICE_FILE="/etc/systemd/system/homecom.service"

if [[ $EUID -ne 0 ]]; then
  echo "Run as root: sudo bash uninstall-homecom.sh"
  exit 1
fi

echo "Uninstalling HomeCom..."

systemctl disable --now homecom.service 2>/dev/null || true
rm -f "$SERVICE_FILE"
systemctl daemon-reload

read -rp "Remove app directory $APP_DIR and all users/certs/data? [y/N]: " CONFIRM
if [[ "$CONFIRM" =~ ^[Yy]$ ]]; then
  rm -rf "$APP_DIR"
fi

read -rp "Remove system user $APP_USER? [y/N]: " CONFIRM_USER
if [[ "$CONFIRM_USER" =~ ^[Yy]$ ]]; then
  userdel "$APP_USER" 2>/dev/null || true
fi

echo "HomeCom removed."
