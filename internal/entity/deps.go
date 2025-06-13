package v1

type Dependency struct {
	Name    string 
	Version string 
	File    string 
	Line    int    
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
