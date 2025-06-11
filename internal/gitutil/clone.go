package gitutil

import (
	"fmt"
	"os"
	"os/exec"
	utils "vuln-scanner/utils/util"

	"github.com/rs/zerolog/log"
)

func Clone(repoURL string) (string, error) {
	log.Info().Msgf("start clone repository: %v", repoURL)
	defer log.Info().Msgf("end clone repository: %v", repoURL)

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
