package analyzers

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	v1 "vuln-scanner/internal/entity"
	"vuln-scanner/utils/dependencies"

	"github.com/rs/zerolog/log"
)

type DepsAnalyzer struct{}

func NewDepsAnalyzer() *DepsAnalyzer { return &DepsAnalyzer{} }

func (a *DepsAnalyzer) Name() string {
	return "Проверка уязвимостей зависимостей"
}

func (a *DepsAnalyzer) Run(repoName, repoPath, branch string) ([]v1.Finding, error) {
	deps, err := gatherDependencies(repoPath)
	if err != nil {
		return nil, err
	}

	// 2) Для каждой зависимости делаем запрос в OSV API
	var findings []v1.Finding
	for _, dep := range deps {
		log.Info().Msgf("now scanning %v@%v", dep.Name, dep.Version)
		vuls, err := dependencies.QueryOSV(dep.Name, dep.Version)
		if err != nil {
			return nil, err
		}
		for _, v := range vuls.Vulns {
			var cve string
			for _, al := range v.Aliases {
				if strings.HasPrefix(al, "CVE-") {
					cve = al
					break
				}
			}

			epssScore, err := dependencies.FetchEPSS(cve)
			if err != nil {
				log.Info().Msgf("failed to get epss: %v", err)
			}

			log.Info().Msgf("name=%v, score=%v", dep.Name, epssScore)
			fmt.Println(epssScore)

			osv := dependencies.MapOSVSeverity(v)
			epss := dependencies.MapEPSS(epssScore)

			findings = append(findings, v1.Finding{
				Branch:   branch,
				File:     dep.File,
				Line:     dep.Line,
				Content:  fmt.Sprintf("%s@%s — %s: %s", dep.Name, dep.Version, v.ID, v.Summary),
				Severity: a.Classify(epss, osv),
				Details:  v.Details,
				EPSS:     epssScore,
			})

		}
	}
	return findings, nil
}

func (a *DepsAnalyzer) Classify(epss, osv v1.SeverityLevel) v1.SeverityLevel {
	sumOfSeverity := int(osv) + int(epss)
	switch {
	case sumOfSeverity >= 5:
		return v1.SevHigh
	case sumOfSeverity >= 3:
		return v1.SevMedium
	default:
		return v1.SevLow
	}
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func gatherDependencies(repoPath string) ([]v1.Dependency, error) {
	var deps []v1.Dependency

	// Go-модули
	goMod := filepath.Join(repoPath, "go.mod")
	if exists(goMod) {
		gs, err := parseGoModules(repoPath, goMod)
		if err != nil {
			return nil, err
		}
		deps = append(deps, gs...)
	}

	// Python requirements
	reqTxt := filepath.Join(repoPath, "requirements.txt")
	if exists(reqTxt) {
		ps, err := parsePythonRequirements(reqTxt)
		if err != nil {
			return nil, err
		}
		deps = append(deps, ps...)
	}

	return deps, nil
}

func parseGoModules(dir, manifest string) ([]v1.Dependency, error) {
	cmd := exec.Command("go", "list", "-m", "-json", "all")
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("go list failed: %w", err)
	}

	dec := json.NewDecoder(bytes.NewReader(out))
	var deps []v1.Dependency
	for {
		var mod struct {
			Path    string
			Version string
		}
		if err := dec.Decode(&mod); err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("decoding go list JSON: %w", err)
		}
		if mod.Path == "" || mod.Version == "" {
			continue
		}
		deps = append(deps, v1.Dependency{
			Name:    mod.Path,
			Version: mod.Version,
			File:    filepath.Base(manifest),
			Line:    0,
		})
	}
	return deps, nil
}

func parsePythonRequirements(manifest string) ([]v1.Dependency, error) {
	f, err := os.Open(manifest)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	var deps []v1.Dependency
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		txt := strings.TrimSpace(scanner.Text())
		if txt == "" || strings.HasPrefix(txt, "#") {
			continue
		}
		parts := strings.SplitN(txt, "==", 2)
		if len(parts) != 2 {
			continue
		}
		deps = append(deps, v1.Dependency{
			Name:    parts[0],
			Version: parts[1],
			File:    filepath.Base(manifest),
			Line:    lineNum,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return deps, nil
}
