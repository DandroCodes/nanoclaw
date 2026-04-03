#!/bin/bash

cd /home/claude-agent/nanoclaw
sudo systemctl stop nanoclaw
npm run build
cd /home/claude-agent/nanoclaw/container
sh build.sh
sudo systemctl start nanoclaw
