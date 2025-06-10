package v1

import "regexp"

var (
	SqlPatterns = []*regexp.Regexp{
		// db.Query("..."+userInput)
		ReQuery,
		// fmt.Sprintf("SELECT ... %s ...", userInput)
		ReSprintf, // inline interpolation через fmt.Errorf или другие функции
		reErrorf,
	}

	ReQuery   = regexp.MustCompile(`(?i)\b(?:db|database)\.(?:Query|Exec)\s*\(\s*"[^"]*"\s*\+\s*`)
	ReSprintf = regexp.MustCompile(`(?i)fmt\.Sprintf\s*\(\s*"[^"]*%s[^"]*",`)
	reErrorf  = regexp.MustCompile(`(?i)(?:fmt\.Errorf|fmt\.Printf)\s*\(\s*"[^"]*%s[^"]*",`)
)
