package analyzers

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"sync"
	"time"
	v1 "vuln-scanner/internal/entity"
	"vuln-scanner/internal/gitutil"
	utils "vuln-scanner/utils/util"

	"github.com/rs/zerolog/log"
)

type job struct {
	repoURL  string
	branch   string
	analyzer Analyzer
}

// ваш слайс анализаторов
var analyzes = []Analyzer{
	NewSecretsAnalyzer(),
	NewSQLInjectionAnalyzer(),
	NewDepsAnalyzer(),
	NewSessionHijackAnalyzer(),
	NewDDoSAnalyzer(),
}

func AnalyzeRepo(ctx context.Context, repoURL string, chatId int64) (v1.AnalyzeResponse, error) {
	tmpDir, err := gitutil.Clone(repoURL)
	if err != nil {
		log.Error().Msgf("[%d] cant clone repo: %v", chatId, err)
		return v1.AnalyzeResponse{}, fmt.Errorf("Не удалось клонировать репозиторий для списка веток")
	}
	defer os.RemoveAll(tmpDir)

	branches, err := gitutil.GetBranches(tmpDir)
	if err != nil {
		log.Error().Msgf("[%d] cant get branches: %v", chatId, err)
		return v1.AnalyzeResponse{}, fmt.Errorf("Не удалось получить список веток")
	}

	jobs := make(chan job)
	results := make(chan []v1.Finding)

	numWorkers := runtime.NumCPU()
	var wg sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
				}

				dir, err := gitutil.Clone(j.repoURL)
				if err != nil {
					log.Error().Msgf("[%d] cant clone repo while analyze: %v", chatId, err)
					continue
				}
				defer os.RemoveAll(dir)

				if err := gitutil.CheckoutBranch(dir, j.branch); err != nil {
					log.Error().Msgf("[%d] cant checkout branch: %v", chatId, err)
					continue
				}

				log.Info().Msgf("[%d] start analyze %v", chatId, j.analyzer.Name())
				finds, err := j.analyzer.Run(utils.ExtractRepoName(j.repoURL), dir, j.branch)
				if err != nil {
					log.Error().Msgf("[%d] error while analyze %v: %v", chatId, j.analyzer.Name(), err)
					continue
				}

				select {
				case results <- finds:
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	go func() {
		for _, branch := range branches {
			for _, analyzer := range analyzes {
				jobs <- job{repoURL: repoURL, branch: branch, analyzer: analyzer}
			}
		}
		close(jobs)
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	var allFindings []v1.Finding
	for f := range results {
		allFindings = append(allFindings, f...)
	}

	return v1.AnalyzeResponse{
		RepositoryName: utils.ExtractRepoName(repoURL),
		AuthorName:     utils.ExtractUserName(repoURL),
		ScanDate:       time.Now(),
		Findings:       allFindings,
	}, nil
}
