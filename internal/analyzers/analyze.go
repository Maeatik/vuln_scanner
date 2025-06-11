package analyzers

import (
	"context"
	"fmt"
	"os"
	v1 "vuln-scanner/internal/entity"
	"vuln-scanner/internal/gitutil"
	utils "vuln-scanner/utils/util"

	"github.com/rs/zerolog/log"
)

var analyzes []Analyzer = []Analyzer{
	NewSecretsAnalyzer(),
	NewSQLInjectionAnalyzer(),
	NewDepsAnalyzer(),
	NewSessionHijackAnalyzer(),
	NewDDoSAnalyzer(),
}

func AnalyzeRepo(ctx context.Context, repoURL string) ([]v1.Finding, error) {
	dir, err := gitutil.Clone(repoURL)
	if err != nil {
		return nil, fmt.Errorf("не удалось клонировать репозиторий: %v", err)
	}
	defer os.RemoveAll(dir)

	repoName := utils.ExtractRepoName(repoURL)
	branches, err := gitutil.GetBranches(dir)
	if err != nil {
		return nil, fmt.Errorf("не удалось получить список веток: %w", err)
	}

	var allFindings []v1.Finding
	for _, branch := range branches {
		if err := gitutil.CheckoutBranch(dir, branch); err != nil {
			log.Warn().Msgf("checkout %v failed: %v", branch, err)
			continue
		}

		for _, analyzer := range analyzes {
			log.Info().Msgf("running %v on %v@%v", analyzer.Name(), repoName, branch)

			finds, err := analyzer.Run(repoName, dir, branch)
			if err != nil {
				log.Error().Err(err).Msgf("analyzer %v error", analyzer.Name())
				continue
			}

			allFindings = append(allFindings, finds...)
		}
	}

	return allFindings, nil
}
