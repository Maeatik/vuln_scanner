package v1

type Dependency struct {
	Name    string // например, "github.com/pkg/errors" или "requests"
	Version string // например, "v0.9.1" или "2.25.1"
	File    string // путь к манифесту, где найдена (go.mod, requirements.txt)
	Line    int    // номер строки (для python), для go всегда 0
}

// XML-структуры для чтения pom.xml
type PomDependency struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
}

type PomModel struct {
	Dependencies []PomDependency `xml:"dependencies>dependency"`
}
