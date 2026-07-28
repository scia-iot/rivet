#!/bin/bash
set -e

# Setup Fish shell configuration for Starship
mkdir -p ~/.config/fish
if ! grep -q "starship init fish" ~/.config/fish/config.fish 2>/dev/null; then
    echo 'starship init fish | source' >> ~/.config/fish/config.fish
fi
starship preset bracketed-segments -o ~/.config/starship.toml

# Install Codex CLI
sudo apt update && sudo apt install bubblewrap
curl -fsSL https://chatgpt.com/codex/install.sh | sh

# Install Python development dependencies
pip install -r requirements-dev.txt
