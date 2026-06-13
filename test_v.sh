#!/bin/bash
cargo run --bin mvis -- tui &
PID=$!
sleep 2
sudo cargo run --bin mvis -- scan $PID -v > v_out.txt
kill $PID
