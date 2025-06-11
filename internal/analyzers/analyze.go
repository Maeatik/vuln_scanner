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

func AnalyzeRepo(ctx context.Context, repoURL string) (v1.AnalyzeResponse, error) {
	// Получаем список веток единожды
	tmpDir, err := gitutil.Clone(repoURL)
	if err != nil {
		return v1.AnalyzeResponse{}, fmt.Errorf("не удалось клонировать репозиторий для списка веток: %v", err)
	}
	// удалим этот временный клон после получения веток
	defer os.RemoveAll(tmpDir)

	branches, err := gitutil.GetBranches(tmpDir)
	if err != nil {
		return v1.AnalyzeResponse{}, fmt.Errorf("не удалось получить список веток: %w", err)
	}

	// Каналы для заданий и результатов
	jobs := make(chan job)
	results := make(chan []v1.Finding)

	// Пул воркеров
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

				// Для каждой задачи заново клонируем репозиторий
				dir, err := gitutil.Clone(j.repoURL)
				if err != nil {
					// неудача клона — пропускаем
					continue
				}
				// cleanup
				defer os.RemoveAll(dir)

				// переключаем ветку
				if err := gitutil.CheckoutBranch(dir, j.branch); err != nil {
					continue
				}

				// запускаем анализатор
				finds, err := j.analyzer.Run(utils.ExtractRepoName(j.repoURL), dir, j.branch)
				if err != nil {
					continue
				}

				// отправляем найденное
				select {
				case results <- finds:
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	// Диспетчер: кладёт в канал все (ветка, анализатор)
	go func() {
		for _, branch := range branches {
			for _, analyzer := range analyzes {
				jobs <- job{repoURL: repoURL, branch: branch, analyzer: analyzer}
			}
		}
		close(jobs)
	}()

	// Закроем results после завершения всех воркеров
	go func() {
		wg.Wait()
		close(results)
	}()

	// Собираем всё из results
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
