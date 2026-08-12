# Obsidian Recon — Setup Guide

AI-Powered Automated Penetration Testing Platform

## Prerequisites (install BEFORE cloning)

### Windows users
1. Install WSL2 + Ubuntu: open PowerShell as Administrator, run `wsl --install`, restart your PC
2. Install Docker Desktop for Windows — during/after setup, enable "Use WSL 2 based engine" in Settings > General, and enable WSL Integration for Ubuntu in Settings > Resources > WSL Integration
3. Do all following steps INSIDE the Ubuntu terminal app, not PowerShell/CMD

### Mac users
1. Install Homebrew (if not already installed):
   `/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"`
2. Install Docker Desktop for Mac: `brew install --cask docker`, then launch it once from Applications
3. Install Git: `brew install git`

### Linux users
1. Install Docker: `sudo apt install -y docker.io docker-compose-plugin` (Ubuntu/Debian) or your distro's equivalent
2. Add yourself to the docker group: `sudo usermod -aG docker $USER`, then log out and back in
3. Install Git: `sudo apt install -y git`

## Setup Steps (same for everyone, once prerequisites are done)

1. Clone the repo:
