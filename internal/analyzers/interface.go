package analyzers

type Analyzer interface {
	Name() string
	Run(repoName, path string) (string, error)
}
