package v1

import "regexp"

var (
	SecretPatterns = []*regexp.Regexp{RePassword, ReSecret, ReApi, ReToken,
		ReAuth, ReLongStroke, ReAWSKey, ReGHToken,
	}

	RePassword   = regexp.MustCompile(`(?i)password\s*[:=]\s*["']?[\w\-!@#$%^&*()_+=]{4,}["']?`)
	ReSecret     = regexp.MustCompile(`(?i)secret\s*[:=]\s*["']?[\w\-!@#$%^&*()_+=]{4,}["']?`)
	ReApi        = regexp.MustCompile(`(?i)api[_-]?key\s*[:=]\s*["']?[A-Za-z0-9_\-]{10,}["']?`)
	ReToken      = regexp.MustCompile(`(?i)token\s*[:=]\s*["']?[A-Za-z0-9\.\-_]{10,}["']?`)
	ReAuth       = regexp.MustCompile(`(?i)Authorization\s*[:=]\s*["']?Bearer\s+[A-Za-z0-9\.\-_]{10,}["']?`)
	ReLongStroke = regexp.MustCompile(`(?i)[a-zA-Z0-9_\-]{32,}`)
	ReAWSKey     = regexp.MustCompile(`AKIA[0-9A-Z]{16}`)
	ReGHToken    = regexp.MustCompile(`ghp_[A-Za-z0-9]{36}`)

	ReConstant      = regexp.MustCompile(`^[A-Z0-9_]+$`)
	ReFuncSignature = regexp.MustCompile(`^\s*func\s`)    // сигнатуры функций
	ReMethodCall    = regexp.MustCompile(`\w+\.\w+\s*\(`) // вызовы методов

	// выводящие функции в Go/JS/Python и т.д.
	OutputPatterns = []*regexp.Regexp{
		regexp.MustCompile(`\bfmt\.Print(?:ln|f)?\s*\(`),
		regexp.MustCompile(`\blog\.(?:Print|Printf|Println|Info|Error|Fatal)\s*\(`),
		regexp.MustCompile(`\bconsole\.log\s*\(`),
		regexp.MustCompile(`\bprint\(`),                   // Python, псевдопринты
		regexp.MustCompile(`\bSystem\.out\.println\s*\(`), // Java
	}

	// переменные, имена которых могут хранить секрет
	VarNamePatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\b\w*(password|passwd|pwd)\w*\b`),
		regexp.MustCompile(`(?i)\b\w*(api[_-]?key|secret|token)\w*\b`),
		regexp.MustCompile(`(?i)\b\w*(auth|credential)\w*\b`),
	}
)
