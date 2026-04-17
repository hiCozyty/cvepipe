#!/bin/bash
JSON_FILE="./output/download_links.json"
TIMEOUT=3600
SESSION="cvepipe"
keys=$(jq -r '.results | keys[]' "$JSON_FILE")

# create single session and start claude
tmux new-session -d -s "$SESSION" -x 220 -y 50
tmux send-keys -t "$SESSION" "claude --dangerously-skip-permissions" Enter

echo "Attach to watch: tmux attach -t $SESSION"
echo "Waiting for Claude to load..."

until tmux capture-pane -t "$SESSION" -p | grep -q "───"; do
  sleep 2
done

echo "Claude ready. Starting pipeline..."

while IFS= read -r key; do
  basename=$(basename "$key")
  final_log="logs/$basename/final.log"

  # skip if already completed
  if [ -f "$final_log" ]; then
    echo "=== Skipping (already done): $key ==="
    continue
  fi

  echo "=== Sending: $key ==="
  tmux send-keys -t "$SESSION" "$key" Enter

  echo "Waiting for $final_log..."
  elapsed=0
  until [ -f "$final_log" ]; do
    sleep 5
    elapsed=$((elapsed + 5))
    if [ "$elapsed" -ge "$TIMEOUT" ]; then
      echo "=== TIMEOUT: $key ==="
      tmux send-keys -t "$SESSION" "" ""
      break
    fi
  done

  echo "=== Done: $key ==="
  sleep 2
  tmux send-keys -t "$SESSION" "/exit" Enter
  sleep 3

  # restart claude for next iteration
  tmux send-keys -t "$SESSION" "claude --dangerously-skip-permissions" Enter
  until tmux capture-pane -t "$SESSION" -p | grep -q "───"; do
    sleep 2
  done

done <<< "$keys"

echo "=== All done ==="