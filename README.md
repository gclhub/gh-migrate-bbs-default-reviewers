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
gh migrate-bbs-default-reviewers [bitbucket-url] [bitbucket-project] [bitbucket-repo] [github-repo] --token [bitbucket-token]
```

### Arguments

- `bitbucket-url`: The base URL of your BitBucket Server instance (e.g., https://bitbucket.example.com)
- `bitbucket-project`: The BitBucket project key
- `bitbucket-repo`: The BitBucket repository name
- `github-repo`: The GitHub repository in `owner/repo` format
- `--token`: BitBucket Server personal access token with read permissions

### Flags

- `--token, -t`: BitBucket Server personal access token (required)
- `--basic-auth, -b`: Use HTTP Basic Authentication instead of Bearer token
- `--version, -v`: Show version information

### Example

```bash
gh migrate-bbs-default-reviewers https://bitbucket.example.com PROJ repo-name owner/migrated-repo --token mytoken123
```

## What it does

1. Fetches default reviewers configuration from BitBucket Server using its REST API
2. Converts the default reviewers into GitHub CODEOWNERS format
3. Creates or updates the `.github/CODEOWNERS` file in the specified GitHub repository

## Requirements

- GitHub CLI (`gh`) installed and authenticated
- BitBucket Server personal access token with read permissions
- Go 1.16 or later for development

## Building from source

```bash
go build -o gh-migrate-bbs-default-reviewers ./cmd/gh-migrate-bbs-default-reviewers
```