#!/usr/bin/env bash
# CTF 赛道技能开关：41 个 competition-* 是否进入 Pi 技能扫描范围
#   ./toggle-ctf.sh off     停用（当前默认，省约 5k 常驻 token）
#   ./toggle-ctf.sh on      启用（打比赛时打开）
#   ./toggle-ctf.sh status  查看当前状态
# 改完在 Pi 里执行 /reload 生效。
set -euo pipefail
cd "$(dirname "$0")"
shopt -s nullglob
TRACKS_LIVE=(CTF-Sandbox-Orchestrator/competition-*)
TRACKS_OFF=(.disabled/competition-*)

case "${1:-status}" in
  off)
    [ ${#TRACKS_LIVE[@]} -eq 0 ] && { echo "已经是停用状态（0 个在扫描范围内）"; exit 0; }
    mkdir -p .disabled
    mv "${TRACKS_LIVE[@]}" .disabled/
    echo "已停用 ${#TRACKS_LIVE[@]} 个赛道技能 -> .disabled/ ；请在 Pi 里执行 /reload"
    ;;
  on)
    [ ${#TRACKS_OFF[@]} -eq 0 ] && { echo "已经是启用状态（0 个在 .disabled/）"; exit 0; }
    mkdir -p CTF-Sandbox-Orchestrator
    mv "${TRACKS_OFF[@]}" CTF-Sandbox-Orchestrator/
    echo "已启用 ${#TRACKS_OFF[@]} 个赛道技能；请在 Pi 里执行 /reload"
    ;;
  status)
    echo "扫描范围内: ${#TRACKS_LIVE[@]} 个 competition-* | .disabled/: ${#TRACKS_OFF[@]} 个"
    ;;
  *) echo "用法: $0 [on|off|status]"; exit 1 ;;
esac
