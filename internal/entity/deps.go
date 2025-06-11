package v1

type Dependency struct {
	Name    string // например, "github.com/pkg/errors" или "requests"
	Version string // например, "v0.9.1" или "2.25.1"
	File    string // путь к манифесту, где найдена (go.mod, requirements.txt)
	Line    int    // номер строки (для python), для go всегда 0
}
