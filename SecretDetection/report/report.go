package report

import (
	"os"
	"strings"

	"SecretDetection/config"
)

const (
	// https://cwe.mitre.org/data/definitions/798.html
	CWE             = "CWE-798"
	CWE_DESCRIPTION = "Use of Hard-coded Credentials"
)

func Write(findings []Finding, cfg config.Config, ext string, reportPath string, noGit bool) error {
	file, err := os.Create(reportPath)
	if err != nil {
		return err
	}
	ext = strings.ToLower(ext)
	switch ext {
	case ".json", "json":
		err = writeJson(findings, file, noGit)
	case ".csv", "csv":
		err = writeCsv(findings, file)
	case ".sarif", "sarif":
		err = writeSarif(cfg, findings, file)
	}

	return err
}
