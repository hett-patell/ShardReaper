---
name: gitmine
description: Automatic git-host recon mine — users/orgs/repos enumeration, commit-history diffing, deleted-secret hunting across Gitea/GitLab/GitHub/Bitbucket, always via blob hashes. Usage: /gitmine <origin>
---

# /gitmine

Git hosts are a recon category, not a one-off. Every Gitea / GitLab /
GitHub / Bitbucket surface gets: user + org + repo enumeration, commit
history walking, and deleted-secret hunting.

## Why blob hashes

Raw file endpoints lie about refs — they serve the ref's CURRENT content,
which is exactly what hides a deleted secret. All content fetches go
through the platform's git BLOBS API, addressed by object hash, so the
content is whatever the hash says it is.

## Usage

```
/shardreaper gitmine http://git.example.com [--token <api-token>] [--deep]
/shardreaper gitmine http://git.example.com --resolve git.example.com=10.0.0.9
```

- `--deep` diffs recent commits (and their parents) so removed secrets are
  diffed out of history
- `--resolve host=ip` — origin-bound transport with curl `--resolve`
  semantics (lesson 16)
- every per-endpoint 404/401 is a skip with a reason, never a fatal

## Output

`{platform, users, orgs, repos, commits_seen, blobs_fetched, secrets[]}` —
secret hits carry `{repo, where (blob <sha> / diff <sha>), kind, snippet}`.
Feed hits straight into `harvest`/`spray`/`remember`.
