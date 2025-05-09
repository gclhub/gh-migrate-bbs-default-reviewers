# gh-migrate-bbs-default-reviewers

A GitHub CLI extension to migrate BitBucket Server default reviewers to GitHub CODEOWNERS.

## Version

Current version: 1.0.0

## Installation

```bash
gh extension install gclhub/gh-migrate-bbs-default-reviewers
```

## Usage

```bash
gh migrate-bbs-default-reviewers [bitbucket-clone-url] [github-repo] --token [bitbucket-token]
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
- `--version, -v`: Show version information

### Example

```bash
# Project repository
gh migrate-bbs-default-reviewers https://bitbucket.example.com/scm/PROJ/repo-name.git owner/migrated-repo --token mytoken123

# User repository
gh migrate-bbs-default-reviewers https://bitbucket.example.com/scm/~username/repo-name.git owner/migrated-repo --token mytoken123
```

## What it does

1. Fetches default reviewers configuration from BitBucket Server using its REST API
2. Converts the default reviewers into GitHub CODEOWNERS format
3. Creates or updates the `.github/CODEOWNERS` file in the specified GitHub repository
4. Creates a repository ruleset that enforces code owner approvals on pull requests
   - Requires at least one approval from a code owner
   - Applies to both main and master branches
   - Repository admins can bypass these restrictions

## Requirements

- GitHub CLI (`gh`) installed and authenticated
- BitBucket Server personal access token with read permissions
- Go 1.16 or later for development
- Destination GitHub repository must exist before running this tool

## Building from source

```bash
go build -o gh-migrate-bbs-default-reviewers ./cmd/gh-migrate-bbs-default-reviewers
```