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
// 递归去除 同时的一对引号(前和后)
func TrimDoubleQuote(s string) string {
	if (s[len(s)-1] == '"' && s[0] == '"') || (s[len(s)-1] == '\'' && s[0] == '\'') {
		return TrimDoubleQuote(s[1 : len(s)-1])
	}

	return s
}

// 递归去除 前或后的 引号
func TrimCustomCharacter(s string) string {
	trimCharacters := []string{"\"", "*", "@", "$", "'", "`", "_", ",", ":", ";", "(", ")", "?", "{", "}", "[", "]"}
	for _, v := range trimCharacters {
		if strings.HasPrefix(s, v) {
			return TrimCustomCharacter(strings.TrimLeft(s, v))
		}
		if strings.HasSuffix(s, v) {
			return TrimCustomCharacter(strings.TrimRight(s, v))
		}
	}
	return s
}

// 密码复杂度等级测评  针对短密码
// 此处分5个级别
const (
	EASY = iota
	MIDIUM
	STRONG
	VERY_STRONG
	EXTREMELY_STRONG
)

// 针对短密码的密码复杂度评级
func PasswordStrengthCheck(s string) int {
	// 返回值应为 0-4的5个整数，如果返回-1则遇到非ascii密码，应该直接舍弃

	strengthScore := 0
	// 【长度加权】
	// pwd长度	8-10: 0  11-13: 2 14-15: 4
	length := len(s)
	if 8 <= length && length <= 10 {
		strengthScore += 10
	} else if 11 <= length && length <= 13 {
		strengthScore += 20
	} else if 14 <= length && length <= 15 {
		strengthScore += 30
	} else {
		strengthScore += 40
	}

	// 【复杂度组合加权】
	//pwd长度		8-10: 0  11-13: 2 14-15: 4
	//数字字符数量	一个2分
	//大写字母字符数量	一个2分
	//小写字母字符数量	一个1分
	//特殊字符_非code	一个4分
	//特殊字符_code	一个1分
	BoolMap := map[string]bool{
		"Digit":  false,
		"Symbol": false,
		//"CodeUsuallySymbol": false,
		"UpCharacter":   false,
		"DownCharacter": false,
	}

	// 这个特殊字符没有 `编程必须字符`
	if containsDigit(s) {
		BoolMap["Digit"] = true
		strengthScore += 5
	}
	if containsSymbol(s) {
		// 这个特殊字符是 `编程必须字符`
		BoolMap["Symbol"] = true
		strengthScore += 10
	}
	//if containsCodeUsuallySymbol(s) {
	//	BoolMap["CodeUsuallySymbol"] = true
	//}
	if containsUpCharacter(s) {
		BoolMap["UpCharacter"] = true
		strengthScore += 5
	}
	if containsDownCharacter(s) {
		BoolMap["DownCharacter"] = true
		strengthScore += 5
	}

	return strengthScore
	// 结合 ShortPasswordCheck(finding.Secret) 算法，开始进行分级分数
	// 分数区间: [8,64] 若低于8说明非ascii，应舍弃
	// EASY 	[8,12)
	// MIDIUM	[12,20)
	// STRONG	[20,28)
	// VERY_STRONG	[28, 59)
	// EXTREMELY_STRONG	[59,64]
	//if 8 <= strengthScore && strengthScore < 12 {
	//	return EASY
	//} else if 12 <= strengthScore && strengthScore < 20 {
	//	return MIDIUM
	//} else if 20 <= strengthScore && strengthScore < 28 {
	//	return STRONG
	//} else if 28 <= strengthScore && strengthScore < 59 {
	//	return VERY_STRONG
	//} else if 59 <= strengthScore && strengthScore <= 64 {
	//	return EXTREMELY_STRONG
	//}
	//return -1
}

// 针对短密码，具备 {大写字母、小写字母、数字、特殊字符} 3/4的检查
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

// 判断字符串是否包含 非 `.`,`_`,`-` 这种编程必须符号 的`特殊字符`
func containsSymbol(s string) bool {
	// 专门缺失 常用的symbol字符 {'.', '_', '-'}
	for _, c := range s {
		switch c {
		case '!', '"', '#', '$', '%', '\'', '(', ')',
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

// 判断字符串是否包含 containsSymbol() 不匹配的 {'.', '_', '-'} 三个字符
func containsCodeUsuallySymbol(s string) bool {
	for _, c := range s {
		switch c {
		case '.', '_', '-':
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

func IsWords(s string) bool {
	// 返回 false表示识别是个密钥，返回 true表示非密钥而变量名
	// 返回越高，说明识别率越高
	// 此处主要处理的是识别到单词类型字符串在 [2,5] 的问题

	// 如果 len==2 长度太短了，不识别，返回1
	//if len(s) <= 2 {
	//	return true
	//}

	//将含有>=5的数字个数直接认为是密钥
	reg_digitNum, err := regexp.Compile(`\d`, 0)
	if err != nil {
		panic(fmt.Errorf("正则表达式编译出现错误"))
	}
	//数字的数量 -> 认为识别率为0
	if len(regexp2FindAllString(reg_digitNum, s)) >= 3 {
		if len(regexp2FindAllString(reg_digitNum, s)) >= 5 {
			return false
		}
	}

	var wordListTotal []string
	// wordListTotal 匹配的是没有特殊字符、数字的 单词类型字符串
	lowAlphaMatchList := regexp2FindAllString(lowAlphaMatchRegexp, s)
	wordListTotal = append(wordListTotal, lowAlphaMatchList...)
	allCaptainAlphaMatchList := regexp2FindAllString(allCaptainAlphaMatchRegexp, s)
	wordListTotal = append(wordListTotal, allCaptainAlphaMatchList...)
	// 切割数量太高，则认为过于琐碎，应该是密钥，返回0
	// 切割数量过短，则认为过于琐碎，应该是密钥，返回0
	if len(wordListTotal) == 1 {
		return false
	}
	if len(wordListTotal) >= 6 {
		return false
	}
	// 满足密码复杂度
	if len(wordListTotal) >= 2 && containsSymbol(s) {
		return false
	}

	// HumanbeingCanReadWordsNum 是单词列表中 标记为 识别为单词的字符串
	var HumanbeingCanReadWordsNum = 0
	for _, single := range wordListTotal {
		if strings.Contains(wordListText, strings.ToLower(single)) {
			HumanbeingCanReadWordsNum++

		} else {
			if len(single) >= 8 {
				// 这类长单词通常有着tion 等一类的后缀，通常我这里去除一下后缀让他看看能不能识别
				if strings.Contains(wordListText, strings.ToLower(single[:len(single)-4])) {
					HumanbeingCanReadWordsNum++
				}
			}
		}
	}

	// 有3个以上的_ 且单词多于2个 则被认为是 编程变量命名的一种
	if strings.Count(s, "_") >= 3 {
		if HumanbeingCanReadWordsNum >= 2 {
			return true
		}
	}

	rate := float32(HumanbeingCanReadWordsNum) / float32(len(wordListTotal))
	//fmt.Println(rate)
	// 先现在要处理的问题是：
	// 以下大于某个值则识别为words，即返回true，不识别为密钥
	// 1 直接返回0 false
	// 2单词里 2识别 1 1识别0.5    	>0.51
	// 3单词里 3识别 1 2识别 0.333	>0.34 y n
	//								>0.67 y
	// 4单词3识别 0.75				>0.76
	// 5单词 3识别 0.6 4识别 0.8 		>0.81
	switch len(wordListTotal) {
	case 2:
		if rate > 0.51 {
			return true
		}
	case 3:
		if rate > 0.67 {
			return true
		}
	case 4:
		if rate > 0.76 {
			return true
		}
	case 5:
		if rate > 0.81 {
			return true
		}
	}

	return false
}

var lowAlphaMatchRegexp, allCaptainAlphaMatchRegexp *regexp.Regexp
var err error

var wordListText string

func init() {
	// 正则表达式
	// 大小写字母开头到小写单词结尾
	lowAlphaMatchRegexp, err = regexp.Compile(`([A-Z][a-z]+|[a-z]+)(?=\b|\d|[A-Z\-_]|[\-_\.])`, 0)
	if err != nil {
		panic(fmt.Errorf("正则表达式编译出现错误"))
	}
	// 零星的全大写字母组成的单词
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
