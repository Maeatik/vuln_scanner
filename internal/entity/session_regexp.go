package v1

import "regexp"

var (
	SetCookiePattern = regexp.MustCompile(`\bhttp\.SetCookie\b|\&http\.Cookie\{`)
	// Ловим выставление HttpOnly:true
	HttpOnlyPattern = regexp.MustCompile(`HttpOnly\s*:\s*true`)
	// Универсальный поиск вызовов куки
	SetCookieCall = regexp.MustCompile(`(?i)(setcookie|cookie\(|SetCookie)`)
)

var SessionPatterns = map[string][]*regexp.Regexp{
	// Go: http.SetCookie / &http.Cookie{ без HttpOnly:true
	".go": {
		regexp.MustCompile(`\bhttp\.SetCookie\(`),
		regexp.MustCompile(`\bhttp\.SetCookie\b|\&http\.Cookie\{`),
		regexp.MustCompile(`&http\.Cookie\{`),
	},
	// Express.js: res.cookie(..., { httpOnly: false })
	".js": {
		regexp.MustCompile(`\.cookie\s*\(\s*['"][^'"]+['"]\s*,\s*[^,]+,\s*\{[^\}]*httpOnly\s*:\s*false[^\}]*\}`),
	},
	// Python Flask: response.set_cookie(..., httponly=False)
	".py": {
		regexp.MustCompile(`\.set_cookie\([^,]+,[^,]*httponly\s*=\s*False`),
	},
	// Java Servlet: cookie.setHttpOnly(false)
	".java": {
		regexp.MustCompile(`\.setHttpOnly\s*\(\s*false\s*\)`),
	},
	// PHP: setcookie(..., httponly\s*false)
	".php": {
		regexp.MustCompile(`setcookie\s*\([^\)]*httponly\s*,\s*false\)`),
	},
	// Ruby Sinatra/Rack: response.set_cookie(..., httponly: false)
	".rb": {
		regexp.MustCompile(`set_cookie\s+[^\}]*httponly:\s*false`),
	},
}
