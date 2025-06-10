package v1

import "regexp"

var SqlPatternsByExt = map[string][]*regexp.Regexp{
	".go": {
		// db.Query("...SELECT ..."+ userInput)
		regexp.MustCompile(`(?i)\b(?:db|database)\.(?:Query|QueryRow|Exec|Prepare)\s*\(\s*"(?:[^"]*\b(?:SELECT|INSERT|UPDATE|DELETE|CREATE|ALTER|DROP|WHERE|FROM|JOIN)\b[^"]*)"\s*\+\s*`),
		// fmt.Sprintf("SELECT ... %s ...", arg)
		regexp.MustCompile(`(?i)fmt\.Sprintf\s*\(\s*"(?:[^"]*\b(?:SELECT|INSERT|UPDATE|DELETE|CREATE|ALTER|DROP|WHERE|FROM|JOIN)\b[^"]*)"\s*,`),
		regexp.MustCompile(`(?i)"[^"]*\b(?:SELECT|INSERT|UPDATE|DELETE|CREATE|ALTER|DROP|WHERE|FROM|JOIN)\b[^"]*"\s*\+\s*[A-Za-z0-9_]+`),
	},
	".py": {
		// cursor.execute("SELECT ..."+ user_input)
		regexp.MustCompile(`(?i)\.execute\s*\(\s*"(?:[^"]*\b(?:SELECT|INSERT|UPDATE|DELETE|CREATE|ALTER|DROP|WHERE|FROM|JOIN)\b[^"]*)"\s*\+\s*`),
		// f"SELECT ... {user}"
		regexp.MustCompile(`(?i)f"[^"]*\b(?:SELECT|INSERT|UPDATE|DELETE|CREATE|ALTER|DROP|WHERE|FROM|JOIN)\b[^"]*\{`),
	},
	".js": {
		// db.query("SELECT ..."+ user)
		regexp.MustCompile(`(?i)\.query\s*\(\s*"(?:[^"]*\b(?:SELECT|INSERT|UPDATE|DELETE|CREATE|ALTER|DROP|WHERE|FROM|JOIN)\b[^"]*)"\s*\+\s*`),
		// template literal: `SELECT ... ${user} ...`
		regexp.MustCompile("`[^`]*\\b(?:SELECT|INSERT|UPDATE|DELETE|CREATE|ALTER|DROP|WHERE|FROM|JOIN)\\b[^`]*\\$\\{"),
	},
	".ts": {
		regexp.MustCompile(`(?i)\.query\s*\(\s*"(?:[^"]*\b(?:SELECT|INSERT|UPDATE|DELETE|CREATE|ALTER|DROP|WHERE|FROM|JOIN)\b[^"]*)"\s*\+\s*`),
		regexp.MustCompile("`[^`]*\\b(?:SELECT|INSERT|UPDATE|DELETE|CREATE|ALTER|DROP|WHERE|FROM|JOIN)\\b[^`]*\\$\\{"),
	},
	".java": {
		// stmt.executeQuery("SELECT ..."+userInput)
		regexp.MustCompile(`(?i)\bStatement\.(?:executeQuery|executeUpdate)\s*\(\s*"(?:[^"]*\b(?:SELECT|INSERT|UPDATE|DELETE|CREATE|ALTER|DROP|WHERE|FROM|JOIN)\b[^"]*)"\s*\+\s*`),
	},
	".php": {
		// mysql_query("SELECT ...".$_GET['id'])
		regexp.MustCompile(`(?i)\b(?:mysql_query|mysqli_query|PDO->query)\s*\(\s*"(?:[^"]*\b(?:SELECT|INSERT|UPDATE|DELETE|CREATE|ALTER|DROP|WHERE|FROM|JOIN)\b[^"]*)"\s*\.\s*\$`),
	},
	".cpp": {
		// sprintf(buf, "SELECT ... %s", user)
		regexp.MustCompile(`(?i)sprintf\s*\(\s*[^,]+,\s*"(?:[^"]*\b(?:SELECT|INSERT|UPDATE|DELETE|CREATE|ALTER|DROP|WHERE|FROM|JOIN)\b[^"]*)"\s*,`),
	},
}
