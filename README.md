# gh-migrate-bbs-default-reviewers

A GitHub CLI extension to migrate BitBucket Server default reviewers to GitHub CODEOWNERS.

## Version

Current version: 1.0.1

## Installation

```bash
gh extension install gclhub/gh-migrate-bbs-default-reviewers
```

## Usage

```bash
gh migrate-bbs-default-reviewers [bitbucket-clone-url] [github-repo] [flags]
```

### Prerequisites

1. Create the destination GitHub repository first:
   ```bash
   gh repo create owner/repo-name
   ```

### Arguments

- `bitbucket-clone-url`: The HTTPS clone URL of your BitBucket Server repository
  - For project repositories: `https://bitbucket.example.com/scm/PROJECT/repository.git`
  - For user repositories: `https://bitbucket.example.com/scm/~username/repository.git`
- `github-repo`: The GitHub repository in `owner/repo` format (must exist)
- `--token`: BitBucket Server personal access token with read permissions

### Flags

- `--token, -t`: BitBucket Server personal access token (required)
- `--basic-auth, -b`: Use HTTP Basic Authentication instead of Bearer token
- `--github-host, -g`: GitHub Enterprise Server hostname (e.g., github.mycompany.com)
- `--version, -v`: Show version information

### Example

```bash
# Project repository on GitHub.com
gh migrate-bbs-default-reviewers https://bitbucket.example.com/scm/PROJ/repo-name.git owner/migrated-repo --token mytoken123

# User repository on GitHub Enterprise Server
gh migrate-bbs-default-reviewers https://bitbucket.example.com/scm/~username/repo-name.git owner/migrated-repo --token mytoken123 --github-host github.mycompany.com
```

## What it does

1. Fetches default reviewers configuration from BitBucket Server using its REST API
2. Converts the default reviewers into GitHub CODEOWNERS format
3. Creates or updates the `.github/CODEOWNERS` file in the specified GitHub repository
4. Creates code review enforcement rules:
   - For GitHub.com and GHES 3.8+:
     - Creates a repository ruleset that enforces code owner approvals
     - Applies to both main and master branches
     - Repository admins can bypass these restrictions
   - For GHES before 3.8:
     - Creates branch protection rules that require code owner reviews
     - Applies to both main and master branches if they exist
     - Requires at least one approval from a code owner
     - Dismisses stale review approvals when new commits are pushed

## Requirements

- GitHub CLI (`gh`) installed and authenticated
- BitBucket Server personal access token with read permissions
- Go 1.16 or later for development
- Destination GitHub repository must exist before running this tool
- For GitHub Enterprise Server:
  - Valid authentication to your GHES instance through the GitHub CLI
  - Uses the `--github-host` flag or `GITHUB_HOST` environment variable
  - Branch protection rules (GHES < 3.8) require GitHub Enterprise or a Pro/Team plan
  - Repository rulesets (GHES ≥ 3.8) work on all repository types

## Building from source

```bash
go build -o gh-migrate-bbs-default-reviewers ./cmd/gh-migrate-bbs-default-reviewers
```
