#!/bin/bash
PROJECT="$HOME/Projects/nta"
IFACE="${NTA_IFACE:-en0}"
API_PORT=8000
UI_PORT=5173

C_ICE='\033[38;5;80m'; C_OK='\033[38;5;79m'; C_WARN='\033[38;5;215m'
C_ERR='\033[38;5;204m'; C_DIM='\033[38;5;245m'; C_OFF='\033[0m'; C_B='\033[1m'

step() { echo -e "  ${C_ICE}▸${C_OFF} $1"; }
ok()   { echo -e "  ${C_OK}✓${C_OFF} $1"; }
warn() { echo -e "  ${C_WARN}!${C_OFF} $1"; }
die()  { echo -e "  ${C_ERR}✗${C_OFF} $1\n"; exit 1; }

cleanup() {
  echo -e "\n\n  ${C_WARN}Shutting down…${C_OFF}"
  [ -n "$PID_TAIL" ] && kill "$PID_TAIL" 2>/dev/null
  [ -n "$PID_UI"  ] && kill "$PID_UI"  2>/dev/null
  [ -n "$PID_API" ] && kill "$PID_API" 2>/dev/null
  [ -n "$PID_CAP" ] && kill "$PID_CAP" 2>/dev/null
  sleep 1
  pkill -f "backend.capture_service" 2>/dev/null
  pkill -f "uvicorn backend.api.main" 2>/dev/null
  pkill -f "vite" 2>/dev/null
  echo -e "  ${C_OK}All processes stopped.${C_OFF}\n"
  exit 0
}
trap cleanup INT TERM

port_busy() { lsof -ti tcp:"$1" >/dev/null 2>&1; }
wait_for_port() {
  local port=$1 label=$2 tries=0
  while ! port_busy "$port"; do
    tries=$((tries+1)); [ "$tries" -gt 50 ] && return 1; sleep 0.5
  done
  ok "$label ready on :$port"
}

clear
echo -e "\n${C_ICE}${C_B}  S E N T I N E L${C_OFF}  ${C_DIM}Network Situational Awareness${C_OFF}\n"

[ -d "$PROJECT" ] || die "Project not found at $PROJECT"
cd "$PROJECT" || die "Cannot enter $PROJECT"
[ -d venv ] || die "No virtualenv found"
source venv/bin/activate
ok "virtualenv active"
[ -d frontend/node_modules ] || die "Run: cd frontend && npm install"

[ -r /dev/bpf0 ] && ok "capture permissions OK" \
  || warn "no /dev/bpf0 access — run: sudo /Library/Application\\ Support/Wireshark/ChmodBPF/ChmodBPF"

ACTUAL=$(route get default 2>/dev/null | awk '/interface:/{print $2}')
[ -n "$ACTUAL" ] && [ "$ACTUAL" != "$IFACE" ] && [ "$IFACE" != "lo0" ] \
  && warn "default route is $ACTUAL, capturing on $IFACE"

for p in $API_PORT $UI_PORT; do
  port_busy "$p" && { warn "freeing port $p"; lsof -ti tcp:"$p" | xargs kill -9 2>/dev/null; sleep 1; }
done

mkdir -p logs
echo ""
step "Starting services"

NTA_IFACE="$IFACE" python -m backend.capture_service > logs/capture.log 2>&1 &
PID_CAP=$!
sleep 2
kill -0 "$PID_CAP" 2>/dev/null && ok "capture on $IFACE" || warn "capture failed — see logs/capture.log"

uvicorn backend.api.main:app --port "$API_PORT" > logs/api.log 2>&1 &
PID_API=$!
wait_for_port "$API_PORT" "api" || warn "api failed — see logs/api.log"

( cd frontend && npm run dev > ../logs/ui.log 2>&1 ) &
PID_UI=$!
wait_for_port "$UI_PORT" "dashboard" || warn "dashboard slow — see logs/ui.log"

sleep 1
open "http://localhost:$UI_PORT"

echo ""
echo -e "  ${C_OK}${C_B}SENTINEL is live${C_OFF}"
echo -e "  ${C_DIM}──────────────────────────────────${C_OFF}"
echo -e "  dashboard  ${C_ICE}http://localhost:$UI_PORT${C_OFF}"
echo -e "  api docs   ${C_ICE}http://localhost:$API_PORT/docs${C_OFF}"
echo -e "  interface  ${C_ICE}$IFACE${C_OFF}"
echo -e "  ${C_DIM}──────────────────────────────────${C_OFF}"
echo -e "  ${C_WARN}Ctrl+C stops everything${C_OFF}\n"

tail -f logs/capture.log 2>/dev/null | grep --line-buffered -E "ALERT|flushed" &
PID_TAIL=$!
wait
