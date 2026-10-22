#!/bin/bash
cd "$(dirname "$0")"
if ! command -v node >/dev/null 2>&1; then
  open "https://nodejs.org/en/download"
  echo " Install Node.js (LTS) first, then run this again."
  read -n 1 -s -r -p "Press any key to close..."
  exit 1
fi
if ! command -v cloudflared >/dev/null 2>&1; then
  if command -v brew >/dev/null 2>&1; then
    echo " Installing the free Cloudflare tunnel tool, one time only..."
    brew install cloudflared
  else
    echo " Please install Homebrew from https://brew.sh first, then run this file again."
    open "https://brew.sh"
    read -n 1 -s -r -p "Press any key to close..."
    exit 1
  fi
fi
export TRUST_PROXY=1
node server.js &
SERVER_PID=$!
trap 'kill $SERVER_PID 2>/dev/null' EXIT
sleep 2
echo
echo " =========================================================="
echo "  Look below for a link like  https://xxxx.trycloudflare.com"
echo "  1. Open THAT link in your browser (not localhost)."
echo "  2. Create the room there, then use the Invite button."
echo "  Keep this window open. Close it to take the app offline."
echo " =========================================================="
echo
cloudflared tunnel --url http://localhost:3000
