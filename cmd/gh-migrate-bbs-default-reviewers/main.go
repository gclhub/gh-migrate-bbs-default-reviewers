package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// Version information has been moved to version.go

type BitbucketDefaultReviewer struct {
	User struct {
		Name         string `json:"name"`
		EmailAddress string `json:"emailAddress"`
		DisplayName  string `json:"displayName"`
	} `json:"user"`
}

type BitbucketDefaultReviewersResponse struct {
	Values        []BitbucketDefaultReviewer `json:"values"`
	Size          int                        `json:"size"`
	Limit         int                        `json:"limit"`
	IsLastPage    bool                       `json:"isLastPage"`
	Start         int                        `json:"start"`
	NextPageStart int                        `json:"nextPageStart"`
}

const maxRetries = 3
const retryDelay = 2 * time.Second

func main() {
	rootCmd := &cobra.Command{
		Use:   "gh-migrate-bbs-default-reviewers [bitbucket-url] [bitbucket-project-or-user] [bitbucket-repo] [github-repo]",
		Short: "Migrate BitBucket Server default reviewers to GitHub CODEOWNERS",
		Long: `Migrate BitBucket Server default reviewers to GitHub CODEOWNERS file.
		
The tool fetches default reviewers from a BitBucket Server repository and creates or updates
a CODEOWNERS file in the specified GitHub repository. It supports both Bearer token and Basic
auth token formats.`,
		Args: func(cmd *cobra.Command, args []string) error {
			if err := cobra.ExactArgs(4)(cmd, args); err != nil {
				return err
			}
			// Validate BitBucket URL
			if _, err := url.Parse(args[0]); err != nil {
				return fmt.Errorf("invalid BitBucket Server URL: %w", err)
			}
			// Validate GitHub repo format
			if !strings.Contains(args[3], "/") {
				return fmt.Errorf("GitHub repository must be in format owner/repo")
			}
			return nil
		},
		RunE: run,
	}

	rootCmd.Flags().StringP("token", "t", "", "BitBucket Server personal access token or basic auth token")
	rootCmd.MarkFlagRequired("token")
	rootCmd.Flags().BoolP("basic-auth", "b", false, "Use HTTP Basic Authentication instead of Bearer token")
	rootCmd.Flags().BoolP("version", "v", false, "Show version information")

	// Version flag handler
	if hasVersionFlag(os.Args[1:]) {
		fmt.Printf("gh-migrate-bbs-default-reviewers version %s\n", VersionInfo())
		os.Exit(0)
	}

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// hasVersionFlag checks if -v or --version flags are present
func hasVersionFlag(args []string) bool {
	for _, arg := range args {
		if arg == "-v" || arg == "--version" {
			return true
		}
	}
	return false
}

func run(cmd *cobra.Command, args []string) error {
	bbsURL := strings.TrimRight(args[0], "/")
	bbsProjectOrUser := args[1]
	bbsRepo := args[2]
	githubRepo := args[3]
	token, _ := cmd.Flags().GetString("token")
	useBasicAuth, _ := cmd.Flags().GetBool("basic-auth")

	fmt.Printf("🔍 Fetching default reviewers from %s/%s...\n", bbsProjectOrUser, bbsRepo)

	// Get default reviewers from BitBucket Server
	reviewers, err := fetchBitbucketDefaultReviewers(bbsURL, bbsProjectOrUser, bbsRepo, token, useBasicAuth)
	if err != nil {
		return fmt.Errorf("failed to fetch default reviewers: %w", err)
	}

	if len(reviewers) == 0 {
		return fmt.Errorf("no default reviewers found in the BitBucket repository")
	}

	fmt.Printf("✅ Found %d default reviewers\n", len(reviewers))
	fmt.Printf("📝 Generating CODEOWNERS content...\n")

	// Convert to CODEOWNERS format
	codeowners := generateCodeowners(reviewers)

	fmt.Printf("🚀 Updating CODEOWNERS file in %s...\n", githubRepo)

	// Print preview of CODEOWNERS content
	fmt.Printf("\nCODEOWNERS preview:\n%s\n", codeowners)

	// Create or update CODEOWNERS file in GitHub
	if err := updateGitHubCodeowners(githubRepo, codeowners); err != nil {
		return fmt.Errorf("failed to update CODEOWNERS: %w", err)
	}

	// Create repository ruleset to enforce code owner approvals
	if err := createCodeOwnersRuleset(githubRepo); err != nil {
		return fmt.Errorf("failed to create repository ruleset: %w", err)
	}

	return nil
}

func fetchBitbucketDefaultReviewers(baseURL, projectOrUser, repo, token string, useBasicAuth bool) ([]BitbucketDefaultReviewer, error) {
	var allReviewers []BitbucketDefaultReviewer

	// Format the auth header according to BitBucket Server documentation
	var authHeader string
	if useBasicAuth {
		// If the token starts with BBDC-, it might be a special format
		// Try to remove the prefix and use as-is
		if strings.HasPrefix(token, "BBDC-") {
			authHeader = "Basic " + strings.TrimPrefix(token, "BBDC-")
		} else {
			authHeader = "Basic " + token
		}
	} else {
		// Standard Bearer token
		authHeader = "Bearer " + token
	}

	// Try alternative authentication formats if the first attempt fails
	authHeaders := []string{
		authHeader,
		"Basic " + token,
		"Bearer " + token,
	}

	// Format the project key - personal repositories use ~username notation
	userOrProjectKey := projectOrUser
	if !strings.HasPrefix(userOrProjectKey, "~") && strings.ToLower(userOrProjectKey) != "public" {
		userOrProjectKey = "~" + userOrProjectKey
	}

	var lastError error

	// Try each auth header format
	for _, authHeader := range authHeaders {
		fmt.Printf("🔍 Trying with auth header: %s***\n", authHeader[:min(len(authHeader), 10)])

		// Try to get repository info - this confirms we can authenticate
		repoEndpoint := fmt.Sprintf("/rest/api/1.0/projects/%s/repos/%s", userOrProjectKey, repo)
		repoURL := baseURL + repoEndpoint

		fmt.Printf("🔍 Fetching repository details: %s\n", repoURL)

		req, err := http.NewRequest("GET", repoURL, nil)
		if err != nil {
			lastError = fmt.Errorf("failed to create request: %w", err)
			continue
		}

		// Add required headers
		req.Header.Set("Authorization", authHeader)
		req.Header.Set("Accept", "application/json")

		client := &http.Client{
			Timeout: 30 * time.Second,
		}

		response, err := client.Do(req)
		if err != nil {
			lastError = fmt.Errorf("failed to connect to BitBucket Server: %w", err)
			continue
		}

		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil {
			lastError = fmt.Errorf("failed to read response: %w", err)
			continue
		}

		fmt.Printf("📝 Repository API response status: %s\n", response.Status)

		// If unauthorized or forbidden, try next auth format
		if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
			lastError = fmt.Errorf("authentication failed - please check your credentials. Response: %s", string(body))
			continue
		}

		// If we get here, authentication worked but repo might not exist
		if response.StatusCode != http.StatusOK {
			lastError = fmt.Errorf("failed to get repository info - HTTP %d: %s", response.StatusCode, string(body))
			continue
		}

		// Parse repository response
		var repoResponse struct {
			ID      int    `json:"id"`
			Slug    string `json:"slug"`
			Project struct {
				Key string `json:"key"`
			} `json:"project"`
		}

		if err := json.Unmarshal(body, &repoResponse); err != nil {
			lastError = fmt.Errorf("failed to parse repository response: %w", err)
			continue
		}

		fmt.Printf("✅ Successfully authenticated and found repository: ID=%d, Slug=%s, Project=%s\n",
			repoResponse.ID, repoResponse.Slug, repoResponse.Project.Key)

		// Now try multiple API paths to get default reviewers
		defaultReviewerPaths := []string{
			fmt.Sprintf("/rest/default-reviewers/1.0/projects/%s/repos/%s/reviewers",
				repoResponse.Project.Key, repoResponse.Slug),
			fmt.Sprintf("/rest/default-reviewers/1.0/projects/%s/repos/%s/conditions",
				repoResponse.Project.Key, repoResponse.Slug),
			fmt.Sprintf("/rest/api/1.0/projects/%s/repos/%s/settings/reviewers",
				repoResponse.Project.Key, repoResponse.Slug),
		}

		// Try each potential default reviewers endpoint
		for _, path := range defaultReviewerPaths {
			reviewersURL := baseURL + path
			fmt.Printf("🔍 Trying to get default reviewers from: %s\n", reviewersURL)

			reviewersReq, err := http.NewRequest("GET", reviewersURL, nil)
			if err != nil {
				continue
			}

			reviewersReq.Header.Set("Authorization", authHeader)
			reviewersReq.Header.Set("Accept", "application/json")

			reviewersResp, err := client.Do(reviewersReq)
			if err != nil || reviewersResp.StatusCode != http.StatusOK {
				if reviewersResp != nil {
					reviewersResp.Body.Close()
				}
				continue
			}

			reviewersBody, err := io.ReadAll(reviewersResp.Body)
			reviewersResp.Body.Close()

			if err != nil {
				continue
			}

			fmt.Printf("📝 Default reviewers API response: %s\n", reviewersResp.Status)
			if len(reviewersBody) > 0 {
				fmt.Printf("📝 Response snippet: %s\n", string(reviewersBody[:min(len(reviewersBody), 200)]))
			}

			// Try to parse reviewers - format depends on the API endpoint
			if strings.Contains(path, "conditions") {
				// Try the exact format we observed in your BitBucket Server response
				var specificConditionsList []struct {
					Reviewers []struct {
						Name         string `json:"name"`
						EmailAddress string `json:"emailAddress"`
						DisplayName  string `json:"displayName"`
						ID           int    `json:"id"`
						Slug         string `json:"slug"`
						Type         string `json:"type"`
					} `json:"reviewers"`
					RequiredApprovals int `json:"requiredApprovals"`
				}

				if err := json.Unmarshal(reviewersBody, &specificConditionsList); err == nil {
					fmt.Printf("📝 Parsing as array of specific conditions\n")
					for _, condition := range specificConditionsList {
						for _, reviewer := range condition.Reviewers {
							r := BitbucketDefaultReviewer{}
							r.User.Name = reviewer.Name
							r.User.EmailAddress = reviewer.EmailAddress
							r.User.DisplayName = reviewer.DisplayName
							allReviewers = append(allReviewers, r)
						}
					}
				} else {
					// Try other formats like before
					var conditionsList []struct {
						ID        string `json:"id"`
						Reviewers []struct {
							User struct {
								Name         string `json:"name"`
								EmailAddress string `json:"emailAddress"`
								DisplayName  string `json:"displayName"`
							} `json:"user"`
						} `json:"reviewers"`
						RequiredApprovals int `json:"requiredApprovals"`
					}

					if err := json.Unmarshal(reviewersBody, &conditionsList); err == nil {
						fmt.Printf("📝 Parsing as array of conditions\n")
						for _, condition := range conditionsList {
							for _, reviewer := range condition.Reviewers {
								r := BitbucketDefaultReviewer{}
								r.User.Name = reviewer.User.Name
								r.User.EmailAddress = reviewer.User.EmailAddress
								r.User.DisplayName = reviewer.User.DisplayName
								allReviewers = append(allReviewers, r)
							}
						}
					} else {
						// Try alternative format with "values" array
						var conditionsResponse struct {
							Values []struct {
								Reviewers []struct {
									User struct {
										Name         string `json:"name"`
										EmailAddress string `json:"emailAddress"`
										DisplayName  string `json:"displayName"`
									} `json:"user"`
								} `json:"reviewers"`
							} `json:"values"`
						}

						if err := json.Unmarshal(reviewersBody, &conditionsResponse); err == nil {
							fmt.Printf("📝 Parsing as object with values array\n")
							for _, condition := range conditionsResponse.Values {
								for _, reviewer := range condition.Reviewers {
									r := BitbucketDefaultReviewer{}
									r.User.Name = reviewer.User.Name
									r.User.EmailAddress = reviewer.User.EmailAddress
									r.User.DisplayName = reviewer.User.DisplayName
									allReviewers = append(allReviewers, r)
								}
							}
						}
					}
				}

				// If still no reviewers, print the full response for debugging
				if len(allReviewers) == 0 {
					fmt.Printf("📝 Could not parse reviewers from conditions response. Full response:\n%s\n", string(reviewersBody))
				}
			} else {
				// Try direct reviewers format
				var reviewersResponse BitbucketDefaultReviewersResponse
				if err := json.Unmarshal(reviewersBody, &reviewersResponse); err == nil {
					allReviewers = append(allReviewers, reviewersResponse.Values...)
				}
			}

			// If we found reviewers, we're done
			if len(allReviewers) > 0 {
				fmt.Printf("✅ Found %d default reviewers\n", len(allReviewers))
				return allReviewers, nil
			}
		}

		// If we got here, we authenticated successfully but found no reviewers
		return nil, fmt.Errorf("authenticated successfully, but no default reviewers found through any API endpoint")
	}

	// If all auth formats failed, return the last error
	return nil, fmt.Errorf("all authentication attempts failed. Last error: %w", lastError)
}

// Helper function to get minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func generateCodeowners(reviewers []BitbucketDefaultReviewer) string {
	var sb strings.Builder
	sb.WriteString("# This file is generated from BitBucket Server default reviewers\n")
	sb.WriteString("# Any manual changes may be overwritten\n\n")

	// Default reviewers in BitBucket apply to all files
	sb.WriteString("# These owners will be the default owners for everything in the repo\n")
	sb.WriteString("* ")

	for i, reviewer := range reviewers {
		if i > 0 {
			sb.WriteString(" ")
		}
		// Use email if available, otherwise username
		if reviewer.User.EmailAddress != "" {
			sb.WriteString(reviewer.User.EmailAddress)
		} else {
			sb.WriteString("@" + reviewer.User.Name)
		}
	}
	sb.WriteString("\n")

	return sb.String()
}

func updateGitHubCodeowners(repo string, content string) error {
	// Check if gh CLI is installed
	fmt.Printf("📝 Checking GitHub CLI...\n")

	// Create CODEOWNERS file using GitHub API
	fmt.Printf("📝 Creating CODEOWNERS file...\n")

	// First, create a temporary file with the content
	tempFile, err := os.CreateTemp("", "CODEOWNERS")
	if err != nil {
		return fmt.Errorf("failed to create temporary file: %w", err)
	}
	defer os.Remove(tempFile.Name())

	// Write the content to the temporary file
	if _, err := tempFile.WriteString(content); err != nil {
		return fmt.Errorf("failed to write to temporary file: %w", err)
	}
	tempFile.Close()

	// Use GitHub API to create or update the file
	uploadCmd := exec.Command("gh", "api",
		fmt.Sprintf("repos/%s/contents/.github/CODEOWNERS", repo),
		"--method", "PUT",
		"-f", fmt.Sprintf("message=Add CODEOWNERS from BitBucket Server default reviewers"),
		"-f", fmt.Sprintf("content=%s", base64Content(content)))

	var stderr bytes.Buffer
	uploadCmd.Stderr = &stderr

	if err := uploadCmd.Run(); err != nil {
		return fmt.Errorf("failed to create CODEOWNERS file: %w - %s", err, stderr.String())
	}

	fmt.Printf("✅ CODEOWNERS file created successfully in %s\n", repo)
	return nil
}

// Helper function to base64 encode content for GitHub API
func base64Content(content string) string {
	return base64.StdEncoding.EncodeToString([]byte(content))
}

func createCodeOwnersRuleset(repo string) error {
	fmt.Printf("📝 Creating repository ruleset to enforce code owner approvals...\n")

	// Create ruleset using GitHub API
	rulesetCmd := exec.Command("gh", "api",
		fmt.Sprintf("repos/%s/rulesets", repo),
		"--method", "POST",
		"-H", "Accept: application/vnd.github+json",
		"-f", "name=Code Owners Review Policy",
		"-f", "target=branch",
		"-f", "enforcement=active",
		"-f", "rules[0][type]=required_reviewers",
		"-f", "rules[0][parameters][required_approving_review_count]=1",
		"-f", "rules[0][parameters][require_code_owner_review]=true",
		"-f", "conditions[ref_name][include][patterns][]=refs/heads/main",
		"-f", "conditions[ref_name][include][patterns][]=refs/heads/master",
		"-f", "bypass_actors[]=repository_admin")

	var stderr bytes.Buffer
	rulesetCmd.Stderr = &stderr

	if err := rulesetCmd.Run(); err != nil {
		return fmt.Errorf("failed to create ruleset: %w - %s", err, stderr.String())
	}

	fmt.Printf("✅ Repository ruleset created successfully\n")
	return nil
}

func extractReviewersFromMap(data map[string]interface{}, reviewers *[]BitbucketDefaultReviewer) {
	for key, value := range data {
		if key == "reviewers" {
			if reviewersArray, ok := value.([]interface{}); ok {
				for _, reviewer := range reviewersArray {
					if reviewerMap, ok := reviewer.(map[string]interface{}); ok {
						r := BitbucketDefaultReviewer{}
						if user, ok := reviewerMap["user"].(map[string]interface{}); ok {
							if name, ok := user["name"].(string); ok {
								r.User.Name = name
							}
							if email, ok := user["emailAddress"].(string); ok {
								r.User.EmailAddress = email
							}
							if displayName, ok := user["displayName"].(string); ok {
								r.User.DisplayName = displayName
							}
						}
						*reviewers = append(*reviewers, r)
					}
				}
			}
		} else if nestedMap, ok := value.(map[string]interface{}); ok {
			extractReviewersFromMap(nestedMap, reviewers)
		}
	}
}
