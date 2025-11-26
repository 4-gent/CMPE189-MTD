#!/bin/bash

echo "[!] Starting Ryu Controller"

ryu-manager ./ryu/main.py &

sleep 3