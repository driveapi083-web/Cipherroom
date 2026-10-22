#!/bin/bash
cd "$(dirname "$0")"
if ! command -v node >/dev/null 2>&1; then
  echo
  echo " Node.js is not installed yet. It is free and needed once."
  echo " A download page will open. Install the LTS version, then double-click this file again."
  open "https://nodejs.org/en/download"
  read -n 1 -s -r -p "Press any key to close..."
  exit 1
fi
echo
echo " Starting CipherRoom. Keep this window open while you chat."
(sleep 2; open "http://localhost:3000") &
node server.js
read -n 1 -s -r -p "Press any key to close..."
