---
name: git-identity
description: Use the correct NullRoute1970 git identity when committing and pushing
metadata:
  audience: ai-agent
  workflow: git
---

## Git Identity
Only ever use this identity for all commits:
- Name: `NullRoute1970`
- Email: `1234567+seconduser@users.noreply.github.com`

## SSH
This repo has `core.sshCommand` set to plink.exe — pageant handles auth.
Do NOT change this config.

## Pre-Push Hook
A hook at `.git/hooks/pre-push` rejects pushes with the wrong author.
Never bypass it — if a push fails, fix the commit author.
