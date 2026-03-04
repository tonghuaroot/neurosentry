#!/bin/bash
# GitHub Repository Setup Script for NeuroSentry
# This script helps you create and push to a GitHub repository

set -e

echo "=========================================="
echo "  NeuroSentry GitHub Setup Script"
echo "=========================================="
echo ""

# Check if git is installed
if ! command -v git &> /dev/null; then
    echo "ERROR: git is not installed"
    exit 1
fi

# Check if gh CLI is installed
if ! command -v gh &> /dev/null; then
    echo "WARNING: GitHub CLI not found"
    echo "Install from: https://cli.github.com/"
    echo ""
    echo "You can create the repo manually at:"
    echo "https://github.com/new"
    echo ""
    read -p "Press Enter to continue with manual setup..."
fi

# Configuration
REPO_NAME="${1:-neurosentry}"
GITHUB_USER="${2:-tonghuaroot}"
PRIVATE="${3:-true}"

echo "Repository Configuration:"
echo "  Owner: $GITHUB_USER"
echo "  Name: $REPO_NAME"
echo "  Private: $PRIVATE"
echo ""

# Initialize git repo if not already
if [ ! -d .git ]; then
    echo "Initializing Git repository..."
    git init
    git branch -M main
fi

# Check current git status
echo ""
echo "Current Git Status:"
git status --short

# Create .gitignore if not exists
if [ ! -f .gitignore ]; then
    echo "No .gitignore found, but should exist"
fi

# Create initial commit if needed
if [ -z "$(git log --oneline 2>/dev/null)" ]; then
    echo ""
    echo "Creating initial commit..."
    git add .
    git commit -m "Initial commit: NeuroSentry AI Runtime Protection System

- eBPF-based kernel-level monitoring
- Model file integrity protection (LSM hooks)
- Network containment (XDP programs)
- AI framework monitoring (Uprobes)
- Complete Docker/K8s deployment
- Interactive Capture The Model challenge
"
fi

# Try to use GitHub CLI if available
if command -v gh &> /dev/null; then
    echo ""
    echo "Creating GitHub repository using gh CLI..."

    # Check if user is authenticated
    if gh auth status &> /dev/null; then
        # Create the repository
        gh repo create "$GITHUB_USER/$REPO_NAME" \
            --private \
            --description "The eBPF-based Guardian for AI Inference Integrity" \
            --source=. \
            --push

        echo ""
        echo "=========================================="
        echo "  Repository created successfully!"
        echo "=========================================="
        echo ""
        echo "Repository URL: https://github.com/$GITHUB_USER/$REPO_NAME"
        echo ""
        echo "Next steps:"
        echo "  1. Visit: https://github.com/$GITHUB_USER/$REPO_NAME/settings"
        echo "  2. Configure branch protection (optional)"
        echo "  3. Add collaborators (optional)"
        echo ""
    else
        echo "ERROR: GitHub CLI not authenticated"
        echo "Run: gh auth login"
        exit 1
    fi
else
    # Manual setup instructions
    echo ""
    echo "=========================================="
    echo "  Manual GitHub Setup Required"
    echo "=========================================="
    echo ""
    echo "Step 1: Create repository on GitHub"
    echo "  Visit: https://github.com/new"
    echo "  Repository name: $REPO_NAME"
    echo "  Private: Yes"
    echo ""
    echo "Step 2: Add remote and push"
    echo "  Run the following commands:"
    echo ""
    echo "  git remote add origin https://github.com/$GITHUB_USER/$REPO_NAME.git"
    echo "  git branch -M main"
    echo "  git push -u origin main"
    echo ""
fi
