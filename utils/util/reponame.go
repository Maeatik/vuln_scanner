package utils

import (
	"path"
	"strings"
)

func ExtractRepoName(repoURL string) string {
	repoURL = strings.TrimSuffix(repoURL, ".git")
	repoURL = strings.Replace(repoURL, ":", "/", 1)

	parts := strings.Split(repoURL, "/")
	if len(parts) == 0 {
		return ""
	}

	return path.Base(parts[len(parts)-1])
}

func ExtractUserName(repoURL string) string {
	repoURL = strings.TrimSuffix(repoURL, ".git")
	repoURL = strings.Replace(repoURL, ":", "/", 1)

	parts := strings.Split(repoURL, "/")
	if len(parts) == 0 {
		return ""
	}

	return path.Base(parts[len(parts)-2])
}
