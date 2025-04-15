package main

// Version information for the GitHub CLI extension
var (
	// Version is the current version of the extension
	Version = "1.0.0"

	// BuildDate is the date when the binary was built
	BuildDate = "2025-04-14"

	// CommitSHA is the git commit SHA at build time
	CommitSHA = "development"
)

// VersionInfo returns a formatted version string
func VersionInfo() string {
	return Version
}

// FullVersionInfo returns complete version information including build date and commit
func FullVersionInfo() string {
	return Version + " (Built: " + BuildDate + ", Commit: " + CommitSHA + ")"
}
