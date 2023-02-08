package detect

import (
	"SecretDetection/bindata"
	"SecretDetection/report"
	"crypto/sha1"
	"encoding/json"
	"fmt"
	regexp "github.com/dlclark/regexp2"
	"github.com/gitleaks/go-gitdiff/gitdiff"
	"github.com/rs/zerolog/log"
	"math"
	"strings"
)

// augmentGitFinding updates the start and end line numbers of a finding to include the
// delta from the git diff
func augmentGitFinding(finding report.Finding, textFragment *gitdiff.TextFragment, f *gitdiff.File) report.Finding {
	if !strings.HasPrefix(finding.Match, "file detected") {
		finding.StartLine += int(textFragment.NewPosition)
		finding.EndLine += int(textFragment.NewPosition)
	}

	// generate finding hash
	h := sha1.New()
	h.Write([]byte(fmt.Sprintf("%s:%s:%s:%d", finding.Commit, finding.File, finding.RuleID, finding.StartLine)))
	finding.Fingerprint = fmt.Sprintf("%x", h.Sum(nil))

	if f.PatchHeader != nil {
		finding.Commit = f.PatchHeader.SHA
		finding.Message = f.PatchHeader.Message()
		if f.PatchHeader.Author != nil {
			finding.Author = f.PatchHeader.Author.Name
			finding.Email = f.PatchHeader.Author.Email
		}
		//finding.Date = f.PatchHeader.AuthorDate.UTC().Format(time.RFC3339)
		// 时间这里改成中国的时间输出格式
		finding.Date = f.PatchHeader.AuthorDate.Format("2006-01-02 15:04:05")
	}
	return finding
}

// shannonEntropy calculates the entropy of data using the formula defined here:
// https://en.wiktionary.org/wiki/Shannon_entropy
// Another way to think about what this is doing is calculating the number of bits
// needed to on average encode the data. So, the higher the entropy, the more random the data, the
// more bits needed to encode that data.
// 香农熵计算
// 此处不区分大小写
func shannonEntropy(data string) (entropy float64) {
	if data == "" {
		return 0
	}

	charCounts := make(map[rune]int)
	for _, char := range data {
		charCounts[char]++
	}

	invLength := 1.0 / float64(len(data))
	// invLength 是个分母，在下两行的代码中使用了乘的方法，故此处提前变分母
	for _, count := range charCounts {
		freq := float64(count) * invLength
		// `freq * math.Log2(freq)` 通常是负数，所以香农熵表示通常是 `-freq * math.Log2(freq)`
		// 所以此处 `entropy -= ...` ，在说所有字符的熵值相加的总和
		entropy -= freq * math.Log2(freq)
	}

	return entropy
}

// 提取 generic的rule下匹配到的 secret 有效值
func GenericRuleSecretExtract(s string) string {
	if (s[len(s)-1] == '"' && s[0] == '"') || (s[len(s)-1] == '\'' && s[0] == '\'') {
		return GenericRuleSecretExtract(s[1 : len(s)-1])
	}

	return s
}

// filter will dedupe and redact findings
func filter(findings []report.Finding, redact bool) []report.Finding {
	var retFindings []report.Finding
	for _, f := range findings {
		include := true
		if strings.Contains(strings.ToLower(f.RuleID), "generic") {
			for _, fPrime := range findings {
				if f.StartLine == fPrime.StartLine &&
					f.Commit == fPrime.Commit &&
					f.RuleID != fPrime.RuleID &&
					strings.Contains(fPrime.Secret, f.Secret) &&
					!strings.Contains(strings.ToLower(fPrime.RuleID), "generic") {

					genericMatch := strings.Replace(f.Match, f.Secret, "REDACTED", -1)
					betterMatch := strings.Replace(fPrime.Match, fPrime.Secret, "REDACTED", -1)
					log.Trace().Msgf("skipping %s finding (%s), %s rule takes precendence (%s)", f.RuleID, genericMatch, fPrime.RuleID, betterMatch)
					include = false
					break
				}
			}
		}

		if redact {
			f.Redact()
		}
		if include {
			retFindings = append(retFindings, f)
		}
	}
	return retFindings
}

func printFinding(f report.Finding) {
	var b []byte
	b, _ = json.MarshalIndent(f, "", "	")
	fmt.Println(string(b))
}

func containsDigit(s string) bool {
	for _, c := range s {
		switch c {
		case '1', '2', '3', '4', '5', '6', '7', '8', '9', '0':
			return true
		}

	}
	return false
}

func containsSymbol(s string) bool {
	// 去掉 ()._-
	for _, c := range s {
		switch c {
		case '!', '"', '#', '$', '%', '\'',
			'*', '+', ',',
			'/', '\\',
			':', ';', '<', '=', '>', '?', '@', '[', ']',
			'^', '`',
			'{', '|',
			'}',
			'~':
			return true
		}

	}
	return false
}

func containsUpCharacter(s string) bool {
	for _, c := range s {
		switch c {
		case 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z':
			return true
		}

	}
	return false
}

func containsDownCharacter(s string) bool {
	for _, c := range s {
		switch c {
		case 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z':
			return true
		}

	}
	return false
}

func UpAndDownRate(s string) float32 {
	if len(s) <= 2 {
		panic(fmt.Errorf("升降值计算，字符过少"))
	}
	var charList []rune
	var UpOrDown uint8
	// UpOrDown 向上为 1 ，向下为 0

	InterruptNum := 0
	for _, singleChar := range s {
		charList = append(charList, rune(singleChar))
	}
	for index, _ := range s {
		if index == 0 {
			continue
		} else {
			if charList[index] > charList[index-1] {
				if UpOrDown != 1 {
					UpOrDown = 1
					InterruptNum += 1
				}
			} else if charList[index] < charList[index-1] {
				if UpOrDown != 0 {
					UpOrDown = 0
					InterruptNum += 1
				}
			}
		}
	}
	return float32(InterruptNum) / float32(len(s))
}

func Split2WordList(s string) float32 {
	if len(s) <= 2 {
		panic(fmt.Errorf("单词识别率计算，字符过少"))
	}

	//将含有>=3的数字个数直接认为是密钥
	reg_digitNum, err := regexp.Compile(`\d`, 0)
	if err != nil {
		panic(fmt.Errorf("正则表达式编译出现错误"))
	}

	//数字的数量 -> 认为识别率为0
	if len(regexp2FindAllString(reg_digitNum, s)) >= 5 {
		return 0
	}

	var wordListTotal []string

	lowAlphaMatchList := regexp2FindAllString(lowAlphaMatchRegexp, s)
	wordListTotal = append(wordListTotal, lowAlphaMatchList...)
	allCaptainAlphaMatchList := regexp2FindAllString(allCaptainAlphaMatchRegexp, s)
	wordListTotal = append(wordListTotal, allCaptainAlphaMatchList...)
	if len(wordListTotal) >= 6 {
		return 0
	}

	if len(wordListTotal) == 0 {
		return 0
	}

	var HumanbeingCanReadWordsNum = 0
	for _, single := range wordListTotal {
		if strings.Contains(wordListText, strings.ToLower(single)) {
			HumanbeingCanReadWordsNum++
		} else {
			if len(single) >= 8 {
				if strings.Contains(wordListText, strings.ToLower(single[:len(single)-4])) {
					HumanbeingCanReadWordsNum++
				}
			}
		}
	}

	if strings.Count(s, "_") >= 3 {
		if HumanbeingCanReadWordsNum >= 2 {
			return 1
		}
	}

	return float32(HumanbeingCanReadWordsNum) / float32(len(wordListTotal))
}

func ShortPasswordCheck(s string) bool {
	IsContainsDigit := containsDigit(s)
	IsContainsSymbol := containsSymbol(s)
	IscontainsUpCharacter := containsUpCharacter(s)
	IsContainsDownCharacter := containsDownCharacter(s)
	BoolMap := []bool{IsContainsDigit, IsContainsSymbol, IscontainsUpCharacter, IsContainsDownCharacter}
	// 4个布尔值，认为其中三个符合则返回true

	BoolNum := 0
	for _, v := range BoolMap {
		if v == true {
			BoolNum++
		}
	}
	if BoolNum >= 3 {
		return true
	}

	return false
}

//func

var lowAlphaMatchRegexp, allCaptainAlphaMatchRegexp *regexp.Regexp
var err error

var wordListText string

func init() {
	lowAlphaMatchRegexp, err = regexp.Compile(`([A-Z][a-z]+|[a-z]+)(?=\b|\d|[A-Z\-_]|[\-_\.])`, 0)
	if err != nil {
		panic(fmt.Errorf("正则表达式编译出现错误"))
	}

	allCaptainAlphaMatchRegexp, err = regexp.Compile(`[A-Z]{2,}(?=\b|\d|[A-Z\-_][a-zA-Z\-_]|[\-_\.])`, 0)
	if err != nil {
		panic(fmt.Errorf("正则表达式编译出现错误"))
	}

	//var wordFilePath = ""
	//wordListTextBytes, err := ioutil.ReadFile(wordFilePath)
	wordListTextBytes, err := bindata.Asset("american-english")

	if err != nil {
		fmt.Println("单词本文件读取失败")
	}
	wordListText = strings.ToLower(string(wordListTextBytes))

}

func regexp2FindAllString(re *regexp.Regexp, s string) []string {
	var matches []string
	m, _ := re.FindStringMatch(s)
	for m != nil {
		matches = append(matches, m.String())
		m, _ = re.FindNextMatch(m)
	}
	return matches
}
