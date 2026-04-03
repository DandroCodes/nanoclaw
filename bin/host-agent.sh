#!/bin/bash
# =============================================================================
# NanoClaw Host Agent
# Executes allowlisted commands from the DOOM container via SSH.
# Installed at: ~/nanoclaw/bin/host-agent.sh
# Invoked via: command= restriction in ~/.ssh/authorized_keys
# =============================================================================

set -euo pipefail

NANOCLAW_DIR="$HOME/nanoclaw"
SCRIPTS_DIR="$NANOCLAW_DIR/groups/discord_main/scripts"
PATCHES_DIR="$NANOCLAW_DIR/groups/discord_main/patches"
ALLOWED_SERVICES="nanoclaw docker"

log() { echo "[host-agent] $*" >&2; }

# Command comes from $SSH_ORIGINAL_COMMAND
CMD="${SSH_ORIGINAL_COMMAND:-}"

if [ -z "$CMD" ]; then
  echo "ERROR: No command provided. Usage: ssh host 'verb arg1 arg2'"
  exit 1
fi

VERB=$(echo "$CMD" | awk '{print $1}')
ARG1=$(echo "$CMD" | awk '{print $2}')
ARG2=$(echo "$CMD" | awk '{print $3}')

case "$VERB" in

  # ---------------------------------------------------------------------------
  # run-script <relative-path>
  # Execute a script from the scripts/ directory.
  # DOOM writes scripts there, then calls this to execute them on the host.
  # ---------------------------------------------------------------------------
  run-script)
    if [ -z "$ARG1" ]; then
      echo "ERROR: run-script requires a path. Example: run-script deploy.sh"
      exit 1
    fi
    SCRIPT_PATH=$(realpath -m "$SCRIPTS_DIR/$ARG1")
    if [[ "$SCRIPT_PATH" != "$SCRIPTS_DIR/"* ]]; then
      echo "ERROR: Path traversal blocked. Script must be within scripts/"
      exit 1
    fi
    if [ ! -f "$SCRIPT_PATH" ]; then
      echo "ERROR: Script not found: $ARG1"
      exit 1
    fi
    chmod +x "$SCRIPT_PATH"
    log "Running script: $SCRIPT_PATH"
    bash "$SCRIPT_PATH"
    ;;

  # ---------------------------------------------------------------------------
  # apply-patch <source-filename> <dest-relative-to-nanoclaw>
  # Copy a file from patches/ to a destination inside ~/nanoclaw/.
  # Example: apply-patch discord.ts src/channels/discord.ts
  # ---------------------------------------------------------------------------
  apply-patch)
    if [ -z "$ARG1" ] || [ -z "$ARG2" ]; then
      echo "ERROR: apply-patch requires <source> <dest>"
      echo "Example: apply-patch discord.ts src/channels/discord.ts"
      exit 1
    fi
    SRC=$(realpath -m "$PATCHES_DIR/$ARG1")
    if [[ "$SRC" != "$PATCHES_DIR/"* ]]; then
      echo "ERROR: Path traversal blocked. Source must be within patches/"
      exit 1
    fi
    DST=$(realpath -m "$NANOCLAW_DIR/$ARG2")
    if [[ "$DST" != "$NANOCLAW_DIR/"* ]]; then
      echo "ERROR: Path traversal blocked. Destination must be within nanoclaw/"
      exit 1
    fi
    if [ ! -f "$SRC" ]; then
      echo "ERROR: Patch file not found: $ARG1"
      exit 1
    fi
    mkdir -p "$(dirname "$DST")"
    cp "$SRC" "$DST"
    log "Applied patch: $ARG1 -> $ARG2"
    echo "OK: $ARG1 -> $ARG2"
    ;;

  # ---------------------------------------------------------------------------
  # systemctl <action> <service>
  # Restart/start/stop/status for allowlisted services only.
  # Allowed services: nanoclaw, docker
  # ---------------------------------------------------------------------------
  systemctl)
    if [ -z "$ARG1" ] || [ -z "$ARG2" ]; then
      echo "ERROR: systemctl requires <action> <service>"
      echo "Example: systemctl restart nanoclaw"
      exit 1
    fi
    if [[ ! "$ARG1" =~ ^(restart|stop|start|status)$ ]]; then
      echo "ERROR: Action must be: restart, stop, start, or status"
      exit 1
    fi
    if [[ ! " $ALLOWED_SERVICES " =~ " $ARG2 " ]]; then
      echo "ERROR: Service not in allowlist: $ARG2 (allowed: $ALLOWED_SERVICES)"
      exit 1
    fi
    log "systemctl $ARG1 $ARG2"
    sudo systemctl "$ARG1" "$ARG2"
    ;;

  # ---------------------------------------------------------------------------
  # docker <subcommand> [args...]
  # Limited Docker operations.
  # ---------------------------------------------------------------------------
  docker)
    DOCKER_ALLOWED="build pull ps images logs inspect"
    if [[ ! " $DOCKER_ALLOWED " =~ " $ARG1 " ]]; then
      echo "ERROR: Docker subcommand not allowed: $ARG1"
      echo "Allowed: $DOCKER_ALLOWED"
      exit 1
    fi
    # Pass remaining args through (strip verb from CMD)
    DOCKER_ARGS="${CMD#docker }"
    log "docker $DOCKER_ARGS"
    docker $DOCKER_ARGS
    ;;

  # ---------------------------------------------------------------------------
  # help — show available commands
  # ---------------------------------------------------------------------------
  help|"")
    cat <<'HELP'
NanoClaw Host Agent — available commands:
  run-script <path>              Run a script from scripts/ directory
  apply-patch <src> <dst>        Copy file from patches/ to nanoclaw/
  systemctl <action> <service>   Control nanoclaw or docker service
  docker <subcommand> [args]     Limited Docker operations
  help                           Show this message
HELP
    ;;

  *)
    echo "ERROR: Unknown command: $VERB"
    echo "Run 'help' for available commands."
    exit 1
    ;;

esac
