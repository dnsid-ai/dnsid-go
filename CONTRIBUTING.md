# Contributing to dnsid-go

Thanks for contributing! This is the Go client SDK for the DNSid protocol.

## Development

```bash
go build ./...
go test ./...
go vet ./...
```

## Pull requests

- Branch off `main`; open a PR against `main`.
- All PRs require **1 approving review** from a code owner and all conversations resolved before merge.
- Keep changes focused; add tests for behavior changes.
- We recommend setting up local signed commits before contributing. Signed commits are the target
  setup for this repository, and repository policy may enable enforcement later.

## Signed commits

GitHub web UI commits are signed by GitHub automatically. Commits you create locally with the Git
CLI need local signing setup to keep contribution history verified and ready for future repository
policy enforcement. Prefer SSH commit signing for this repository; it requires Git 2.34 or newer.

These commands are self-contained for this SDK repo and follow GitHub's signed-commit setup guides:
[telling Git about your signing key](https://docs.github.com/en/authentication/managing-commit-signature-verification/telling-git-about-your-signing-key)
and [signing commits](https://docs.github.com/en/authentication/managing-commit-signature-verification/signing-commits).

Check your Git version and choose an SSH signing key. To reuse an existing key, set
`SSH_SIGNING_KEY` to the private key path before each block you run.

```bash
set -euo pipefail

git --version

git_email="$(git config user.email || true)"
if [ -z "$git_email" ]; then
  echo "Set git user.email before configuring signing."
  exit 1
fi

export SSH_SIGNING_KEY="${SSH_SIGNING_KEY:-$HOME/.ssh/id_ed25519_signing}"
mkdir -p "$(dirname "$SSH_SIGNING_KEY")"

if [ -f "$SSH_SIGNING_KEY" ] && [ ! -f "${SSH_SIGNING_KEY}.pub" ]; then
  temp_pub="$(mktemp)" || exit 1
  if ssh-keygen -y -f "$SSH_SIGNING_KEY" > "$temp_pub"; then
    mv "$temp_pub" "${SSH_SIGNING_KEY}.pub"
  else
    rm -f "$temp_pub"
    exit 1
  fi
elif [ ! -f "$SSH_SIGNING_KEY" ] && [ -f "${SSH_SIGNING_KEY}.pub" ]; then
  echo "Found ${SSH_SIGNING_KEY}.pub but not $SSH_SIGNING_KEY; choose a key with its private key."
  exit 1
elif [ ! -f "$SSH_SIGNING_KEY" ]; then
  ssh-keygen -t ed25519 -C "$git_email" -f "$SSH_SIGNING_KEY"
fi

expected_pub="$(mktemp)" || exit 1
if ssh-keygen -y -f "$SSH_SIGNING_KEY" > "$expected_pub"; then
  if ! cmp -s "$expected_pub" "${SSH_SIGNING_KEY}.pub"; then
    echo "${SSH_SIGNING_KEY}.pub does not match $SSH_SIGNING_KEY."
    rm -f "$expected_pub"
    exit 1
  fi
else
  rm -f "$expected_pub"
  exit 1
fi
rm -f "$expected_pub"
```

Upload the public key to GitHub as a signing key, then configure this checkout to sign commits and
tags with SSH by default. Run these commands from the `dnsid-go` repository root. If `gh` reports a
missing `admin:ssh_signing_key` scope, run
`gh auth refresh -h github.com -s admin:ssh_signing_key`, then retry the upload.

```bash
set -euo pipefail

export SSH_SIGNING_KEY="${SSH_SIGNING_KEY:-$HOME/.ssh/id_ed25519_signing}"
test -f "${SSH_SIGNING_KEY}.pub"

gh ssh-key add "${SSH_SIGNING_KEY}.pub" --type signing --title "$(hostname)-dnsid-go signing"

git config gpg.format ssh
git config user.signingkey "${SSH_SIGNING_KEY}.pub"
git config commit.gpgsign true
git config tag.gpgsign true
```

Verify that the email configured in Git is verified on GitHub. If the API command reports a missing
`user` scope, run `gh auth refresh -h github.com -s user`, then retry it. If the command returns no
row or `verified: false`, verify the email in GitHub before committing.

```bash
git_email="$(git config user.email || true)"
if [ -z "$git_email" ]; then
  echo "Set git user.email before verifying signing."
  exit 1
fi
if [ -n "${GIT_AUTHOR_EMAIL:-}" ] || [ -n "${GIT_COMMITTER_EMAIL:-}" ]; then
  echo "Unset GIT_AUTHOR_EMAIL and GIT_COMMITTER_EMAIL before verifying signing."
  exit 1
fi
gh api user/emails --jq ".[] | select(.email == \"$git_email\") | {email, verified}"
```

Create and verify a throwaway signed commit on a temporary branch. Run this from a clean worktree.
For external contributors, set `test_remote` to your fork remote if you cannot push branches to the
upstream repository.

```bash
set -euo pipefail

export SSH_SIGNING_KEY="${SSH_SIGNING_KEY:-$HOME/.ssh/id_ed25519_signing}"
test -f "${SSH_SIGNING_KEY}.pub"

test_branch="verify-signed-commit-setup-$(date +%s)"
current_branch="$(git branch --show-current)"
test_remote="${test_remote:-origin}"
remote_branch_pushed=0

cleanup() {
  git switch "$current_branch" >/dev/null 2>&1 || true
  if [ "$remote_branch_pushed" -eq 1 ]; then
    git push "$test_remote" --delete "$test_branch" >/dev/null 2>&1 || true
  fi
  git branch -D "$test_branch" >/dev/null 2>&1 || true
}
trap cleanup EXIT

test_repo="$(
  git remote get-url --push "$test_remote" |
    sed -E 's#^git@github.com:##; s#^ssh://git@github.com/##; s#^https://([^@/]+@)?github.com/##; s#/$##; s#\.git$##'
)"
if ! printf '%s\n' "$test_repo" | grep -Eq '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$'; then
  echo "Could not derive owner/repo from $test_remote push URL."
  exit 1
fi
git_email="$(git config user.email || true)"
if [ -z "$git_email" ]; then
  echo "Set git user.email before verifying signing."
  exit 1
fi
if [ -n "${GIT_AUTHOR_EMAIL:-}" ] || [ -n "${GIT_COMMITTER_EMAIL:-}" ]; then
  echo "Unset GIT_AUTHOR_EMAIL and GIT_COMMITTER_EMAIL before verifying signing."
  exit 1
fi
if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "Commit or stash changes before creating the throwaway signed commit."
  exit 1
fi

git switch -c "$test_branch"
git commit --allow-empty -S -m "test: verify signed commit setup"

mkdir -p ~/.config/git
allowed_signers="$HOME/.config/git/allowed_signers"
allowed_signer="$git_email $(cat "${SSH_SIGNING_KEY}.pub")"
touch "$allowed_signers"
grep -qxF "$allowed_signer" "$allowed_signers" || printf '%s\n' "$allowed_signer" >> "$allowed_signers"
git config gpg.ssh.allowedSignersFile "$allowed_signers"

git verify-commit HEAD
git log --show-signature -1

git push -u "$test_remote" "$test_branch"
remote_branch_pushed=1
gh api "repos/$test_repo/commits/$(git rev-parse HEAD)" --jq '.commit.verification'
```

## Reporting security issues

See [SECURITY.md](SECURITY.md) — do not file public issues for vulnerabilities.
