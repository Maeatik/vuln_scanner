package gitutil

import (
	"bytes"
	"os/exec"
	"strings"

	"github.com/rs/zerolog/log"
)

func GetBranches(repoPath string) ([]string, error) {
	log.Info().Msgf("start get branches")
	defer log.Info().Msgf("end clone repository")

	cmd := exec.Command("git", "-C", repoPath, "branch", "-r")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return nil, err
	}

	var branches []string
	for _, line := range strings.Split(out.String(), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.Contains(line, "->") {
			continue
		}
		// Пример: origin/dev → dev
		parts := strings.SplitN(line, "/", 2)
		if len(parts) == 2 {
			branches = append(branches, parts[1])
		}
	}
	return branches, nil
}

// CheckoutBranch переключается на указанную ветку
func CheckoutBranch(repoPath, branch string) error {
	cmd := exec.Command("git", "-C", repoPath, "checkout", "--quiet", branch)
	return cmd.Run()
}
