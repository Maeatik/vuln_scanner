package v1 

var (
	SupportedExtensions = []string{
		".go", ".py", ".js", ".ts", ".java", ".c", ".cpp", ".h", ".hpp", ".php", ".sh",
		".env", ".yml", ".yaml", ".json",
	}

	IgnoredFilenames = []string{
		"go.mod", "go.sum",
		"requirements.txt", "Pipfile", "Pipfile.lock",
		"package.json", "package-lock.json", "yarn.lock",
		"pom.xml", "build.gradle", "build.gradle.kts",
		"composer.lock", "composer.json",
	}
)
