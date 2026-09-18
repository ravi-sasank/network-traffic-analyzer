#!/bin/bash
# SENTINEL on loopback — for demoing with the attack simulator.
# The simulator targets 127.0.0.1, so capture must listen on lo0 to see it.
export NTA_IFACE=lo0
exec "$(dirname "$0")/sentinel.command"
