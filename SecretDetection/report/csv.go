package report

import (
	"encoding/csv"
	"io"
	"strconv"
)

// writeCsv writes the list of findings to a writeCloser.
func writeCsv(f []Finding, w io.WriteCloser) error {
	if len(f) == 0 {
		return nil
	}
	defer w.Close()
	/* 处理导出CSV中文乱码 bug*/
	w.Write([]byte("\xEF\xBB\xBF"))
	cw := csv.NewWriter(w)
	err := cw.Write([]string{
		"规则ID",
		"描述",
		"Commit",
		"文件位置",
		"凭证",
		"密码强度",
		"香农熵",
		"匹配内容",
		"开始行",
		"结束行",
		"开始列",
		"结束列",
		"提交者",
		"提交信息",
		"提交时间",
		"邮箱",
		"Commit指纹",
	})
	if err != nil {
		return err
	}
	for _, f := range f {
		err = cw.Write([]string{
			f.RuleID,
			f.Description,
			f.Commit,
			f.File,
			f.Secret,
			strconv.Itoa(f.ScoreStrength),
			strconv.FormatFloat(float64(f.Entropy), 'f', 2, 32),
			f.Match,
			strconv.Itoa(f.StartLine),
			strconv.Itoa(f.EndLine),
			strconv.Itoa(f.StartColumn),
			strconv.Itoa(f.EndColumn),
			f.Author,
			f.Message,
			f.Date,
			f.Email,
			f.Fingerprint,
		})
		if err != nil {
			return err
		}
	}

	cw.Flush()
	return cw.Error()
}
