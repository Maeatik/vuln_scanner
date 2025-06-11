package utils

import (
	"path"
	"strings"
)

// ExtractRepoName получает имя репозитория из URL
func ExtractRepoName(repoURL string) string {
	// Удаляем .git в конце, если есть
	repoURL = strings.TrimSuffix(repoURL, ".git")

	// Пример: https://github.com/user/repo → parts = [github.com user repo]
	// Пример: git@github.com:user/repo → заменим ":" на "/" и сплитнем
	repoURL = strings.Replace(repoURL, ":", "/", 1)

	// Обрезаем всё до имени репозитория
	parts := strings.Split(repoURL, "/")
	if len(parts) == 0 {
		return ""
	}

	return path.Base(parts[len(parts)-1])
}

func ExtractUserName(repoURL string) string {
	// Удаляем .git в конце, если есть
	repoURL = strings.TrimSuffix(repoURL, ".git")

	// Пример: https://github.com/user/repo → parts = [github.com user repo]
	// Пример: git@github.com:user/repo → заменим ":" на "/" и сплитнем
	repoURL = strings.Replace(repoURL, ":", "/", 1)

	// Обрезаем всё до имени репозитория
	parts := strings.Split(repoURL, "/")
	if len(parts) == 0 {
		return ""
	}

	return path.Base(parts[len(parts)-2])
}
