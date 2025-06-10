package gitutil

import (
	"fmt"
	"os"
	"os/exec"
	utils "vuln-scanner/utils/util"
)

func Clone(repoURL string) (string, error) {
	repoName := utils.ExtractRepoName(repoURL)

	dir, err := os.MkdirTemp("", repoName+"-*")
	if err != nil {
		return "", fmt.Errorf("не удалось создать временную директорию: %w", err)
	}

	cmd := exec.Command("git", "clone", "--quiet", repoURL, dir)

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("ошибка при клонировании репозитория: %w", err)
	}

	return dir, nil
}
