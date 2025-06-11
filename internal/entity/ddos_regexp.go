package v1

import "regexp"

var (
	// прямой запуск сервера
	ListenPattern = regexp.MustCompile(`\bhttp\.ListenAndServe\(`)
	// явная конфигурация сервера
	ServerPattern = regexp.MustCompile(`&http\.Server\s*\{`)
	// флаги таймаутов
	TimeoutPattern = regexp.MustCompile(`(ReadTimeout|WriteTimeout|IdleTimeout)\s*:`)

	PyDDOSPattern   = regexp.MustCompile(`(?i)app\.run\(`)
	JavaDDOSPattern = regexp.MustCompile(`ServletWebServerFactory\s*\(\)`)
)
