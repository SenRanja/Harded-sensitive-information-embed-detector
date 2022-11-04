package report

import (
	"encoding/json"
	"io"
)

func writeJson(findings []Finding, w io.WriteCloser, noGit bool) error {
	if len(findings) == 0 {
		findings = []Finding{}
	}
	type resjson struct {
		ScanSourceMode string    `json:"ScanSource"`
		Res            []Finding `json:"ScanRes"`
	}

	var resjson_obj resjson
	if noGit {
		resjson_obj.ScanSourceMode = `LocalScan`
	} else {
		resjson_obj.ScanSourceMode = `GitScan`
	}

	resjson_obj.Res = findings

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", " ")
	return encoder.Encode(resjson_obj)
}
