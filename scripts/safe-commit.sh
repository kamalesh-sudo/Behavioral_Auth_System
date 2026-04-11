#!/usr/bin/env bash

set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/safe-commit.sh "commit message"

What it does:
  1) Plans what should be pushed vs not pushed.
  2) Blocks obvious sensitive/runtime files.
  3) Stages recommended files in patch mode.
  4) Shows staged diff for final review.
  5) Commits only after explicit confirmation.
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ $# -lt 1 ]]; then
  usage
  exit 1
fi

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "Error: run this inside a git repository."
  exit 1
fi

commit_message="$*"

classify_file() {
  local file="$1"
  case "$file" in
    .env|.env.local|.env.*.local|.venv/*|*.pem|*.key|*.p12|*.crt)
      echo "never"
      ;;
    backend/users.db|*.db|*.sqlite|*.sqlite3|backend/models/*.pkl|backend/models/*.h5|models/*.pkl|models/*.h5)
      echo "ask"
      ;;
    *)
      echo "recommended"
      ;;
  esac
}

echo
echo "== Branch =="
git branch --show-current
echo

echo "== Current Status =="
git status --short
echo

mapfile -t changed_files < <(
  (
    git diff --name-only
    git diff --name-only --cached
    git ls-files --others --exclude-standard
  ) | awk 'NF' | sort -u
)

if [[ ${#changed_files[@]} -eq 0 ]]; then
  echo "No changes detected. Nothing to commit."
  exit 0
fi

recommended_files=()
ask_first_files=()
never_files=()

for file in "${changed_files[@]}"; do
  category="$(classify_file "$file")"
  case "$category" in
    recommended) recommended_files+=("$file") ;;
    ask) ask_first_files+=("$file") ;;
    never) never_files+=("$file") ;;
  esac
done

echo "== Commit Plan =="
echo
echo "Recommended to push:"
if [[ ${#recommended_files[@]} -eq 0 ]]; then
  echo "  (none)"
else
  for file in "${recommended_files[@]}"; do
    echo "  - $file"
  done
fi
echo

echo "Ask first before pushing:"
if [[ ${#ask_first_files[@]} -eq 0 ]]; then
  echo "  (none)"
else
  for file in "${ask_first_files[@]}"; do
    echo "  - $file"
  done
fi
echo

echo "Never push directly:"
if [[ ${#never_files[@]} -eq 0 ]]; then
  echo "  (none)"
else
  for file in "${never_files[@]}"; do
    echo "  - $file"
  done
fi
echo

mapfile -t staged_files_now < <(git diff --cached --name-only)
if [[ ${#staged_files_now[@]} -gt 0 ]]; then
  blocked_staged=()
  for file in "${staged_files_now[@]}"; do
    if [[ "$(classify_file "$file")" == "never" ]]; then
      blocked_staged+=("$file")
    fi
  done

  if [[ ${#blocked_staged[@]} -gt 0 ]]; then
    echo "Error: sensitive/runtime files are already staged:"
    for file in "${blocked_staged[@]}"; do
      echo "  - $file"
    done
    echo
    echo "Run: git restore --staged <file>  (for each file above)"
    exit 1
  fi
fi

if [[ ${#recommended_files[@]} -gt 0 ]]; then
  read -r -p "Stage recommended files using patch mode now? [Y/n] " stage_answer
  stage_answer="${stage_answer:-Y}"
  if [[ "$stage_answer" =~ ^[Yy]$ ]]; then
    git add -p -- "${recommended_files[@]}"
  else
    echo "Skipped staging step. Stage manually before commit."
  fi
elseYou are an autonomous AI Architect. Your task is to bootstrap the project's agent framework and system design documentation.



1.  **Analyze** the current codebase structure, dependencies, and any existing documentation.

 2.  **Create** two files in the project root:

    *   `AGENTS.md`: Define key agent roles (e.g., Architect, Developer, Tester) with their specific goals, deliverables, and handoff conditions. Use the structure from community best practices.

    *   `ARCHITECTURE.md`: Document the system's target service design, data model, API overview, and validation plan based on the code analysis.

3.  **Execute** by writing these files to the workspace.  
  echo "No recommended files to stage."
fi
echo

if git diff --cached --quiet; then
  echo "No staged changes to commit. Aborting."
  exit 1
fi

echo "== Staged Summary =="
git diff --cached --stat
echo

read -r -p "Show full staged diff before commit? [y/N] " show_diff
if [[ "$show_diff" =~ ^[Yy]$ ]]; then
  git diff --cached
fi
echo

read -r -p "Create commit now with message: \"$commit_message\" ? [y/N] " confirm
if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
  echo "Commit cancelled."
  exit 1
fi

git commit -m "$commit_message"
echo
echo "Commit created safely."
