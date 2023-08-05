package detect

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"SecretDetection/config"
	"SecretDetection/detect/git"
	"SecretDetection/report"

	"github.com/fatih/semgroup"
	"github.com/gitleaks/go-gitdiff/gitdiff"
	"github.com/h2non/filetype"
	ahocorasick "github.com/petar-dambovaliev/aho-corasick"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
)

type GitScanType int

const (
	DetectType GitScanType = iota
	ProtectType
	ProtectStagedType
)

// Detector is the main detector struct
type Detector struct {
	// Config is the configuration for the detector
	Config config.Config

	Redact bool

	// verbose is a flag to print findings
	Verbose bool

	// commitMap is used to keep track of commits that have been scanned.
	// This is only used for logging purposes and git scans.
	commitMap map[string]bool

	// findingMutex is to prevent concurrent access to the
	// findings slice when adding findings.
	findingMutex *sync.Mutex

	// findings is a slice of report.Findings. This is the result
	// of the detector's scan which can then be used to generate a
	// report.
	findings []report.Finding

	// prefilter is a ahocorasick struct used for doing efficient string
	// matching given a set of words (keywords from the rules in the config)
	prefilter ahocorasick.AhoCorasick

	secretDetectionIgnore map[string]bool
}

// Fragment contains the data to be scanned
type Fragment struct {
	// Raw is the raw content of the fragment
	Raw string

	// FilePath is the path to the file if applicable
	FilePath string

	// CommitSHA is the SHA of the commit if applicable
	CommitSHA string

	// newlineIndices is a list of indices of newlines in the raw content.
	// This is used to calculate the line location of a finding
	newlineIndices [][]int

	// keywords is a map of all the keywords contain within the contents
	// of this fragment
	keywords map[string]bool
}

// NewDetector creates a new detector with the given config
func NewDetector(cfg config.Config) *Detector {
	builder := ahocorasick.NewAhoCorasickBuilder(ahocorasick.Opts{
		AsciiCaseInsensitive: true,
		MatchOnlyWholeWords:  false,
		MatchKind:            ahocorasick.LeftMostLongestMatch,
		DFA:                  true,
	})

	return &Detector{
		commitMap:             make(map[string]bool),
		secretDetectionIgnore: make(map[string]bool),
		findingMutex:          &sync.Mutex{},
		findings:              make([]report.Finding, 0),
		Config:                cfg,
		prefilter:             builder.Build(cfg.Keywords),
	}
}

// NewDetectorDefaultConfig creates a new detector with the default config
func NewDetectorDefaultConfig() (*Detector, error) {
	viper.SetConfigType("toml")
	err := viper.ReadConfig(strings.NewReader(config.DefaultConfig))
	if err != nil {
		return nil, err
	}
	var vc config.ViperConfig
	err = viper.Unmarshal(&vc)
	if err != nil {
		return nil, err
	}
	cfg, err := vc.Translate()
	if err != nil {
		return nil, err
	}
	return NewDetector(cfg), nil
}

func (d *Detector) AddSecretDetectionIgnore(secretDetectionIgnorePath string) error {
	file, err := os.Open(secretDetectionIgnorePath)

	if err != nil {
		return err
	}

	defer file.Close()
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		d.secretDetectionIgnore[scanner.Text()] = true
	}
	return nil
}

// DetectBytes scans the given bytes and returns a list of findings
func (d *Detector) DetectBytes(content []byte) []report.Finding {
	return d.DetectString(string(content))
}

// DetectString scans the given string and returns a list of findings
func (d *Detector) DetectString(content string) []report.Finding {
	return d.Detect(Fragment{
		Raw: content,
	})
}

// detectRule scans the given fragment for the given rule and returns a list of findings
// 根据规则进行计算和过滤，然后该函数返回findings列表
// DetectGit() 和 DetectFiles() 都会调用Detect()，然后Detect()会调用此处的detectRule()
func (d *Detector) detectRule(fragment Fragment, rule config.Rule) []report.Finding {
	var findings []report.Finding

	// check if filepath or commit is allowed for this rule
	// commit 是否被设置为 `允许忽略`
	if rule.Allowlist.CommitAllowed(fragment.CommitSHA) ||
		rule.Allowlist.PathAllowed(fragment.FilePath) {
		return findings
	}

	if rule.Path != nil && rule.Regex == nil {
		// Path _only_ rule
		if rule.Path.Match([]byte(fragment.FilePath)) {
			finding := report.Finding{
				Description: rule.Description,
				File:        fragment.FilePath,
				RuleID:      rule.RuleID,
				Match:       fmt.Sprintf("file detected: %s", fragment.FilePath),
				Tags:        rule.Tags,
			}
			return append(findings, finding)
		}
	} else if rule.Path != nil {
		// if path is set _and_ a regex is set, then we need to check both
		// so if the path does not match, then we should return early and not
		// consider the regex
		if !rule.Path.Match([]byte(fragment.FilePath)) {
			return findings
		}
	}

	// if path only rule, skip content checks
	if rule.Regex == nil {
		return findings
	}
	// 这里对文件内容进行正则匹配，获取本规则在本文件中匹配的所有结果
	// matchIndices是 某个单个[[rule]] 的正则匹配本文件内容，返回的全部的匹配值
	matchIndices := rule.Regex.FindAllStringIndex(fragment.Raw, -1)
	for _, matchIndex := range matchIndices {
		// 这个遍历就是检测凭证算法

		// 以下很长的我没有中文注释的内容均是对secret进行过滤，我们的过滤要写在该部分之后
		// extract secret from match
		secret := strings.Trim(fragment.Raw[matchIndex[0]:matchIndex[1]], "\n")

		// determine location of match. Note that the location
		// in the finding will be the line/column numbers of the _match_
		// not the _secret_, which will be different if the secretGroup
		// value is set for this rule
		loc := location(fragment, matchIndex)

		finding := report.Finding{
			Description:   rule.Description,
			File:          fragment.FilePath,
			RuleID:        rule.RuleID,
			StartLine:     loc.startLine,
			EndLine:       loc.endLine,
			StartColumn:   loc.startColumn,
			EndColumn:     loc.endColumn,
			Secret:        secret,
			Match:         secret,
			Tags:          rule.Tags,
			ScoreStrength: 0,
		}

		// check if the secret is in the allowlist
		if rule.Allowlist.RegexAllowed(finding.Secret) ||
			d.Config.Allowlist.RegexAllowed(finding.Secret) {
			continue
		}

		// toml配置文件中的 Group 不是随便设置的
		// extract secret from secret group if set
		if rule.SecretGroup != 0 {
			groups := rule.Regex.FindStringSubmatch(secret)
			if len(groups) <= rule.SecretGroup || len(groups) == 0 {
				// Config validation should prevent this
				continue
			}
			secret = groups[rule.SecretGroup]
			finding.Secret = secret
		}

		// check if the secret is in the list of stopwords
		if rule.Allowlist.ContainsStopWord(finding.Secret) ||
			d.Config.Allowlist.ContainsStopWord(finding.Secret) {
			continue
		}

		// 过滤转义字符
		finding.Secret = TrimHTMLSpecialChars(finding.Secret)

		// secret手动对模糊匹配的secret进行一下左侧和右侧影响字符的过滤
		if finding.Secret != "" && strings.HasPrefix(rule.RuleID, "generic") {
			finding.Secret = TrimDoubleQuote(finding.Secret)
		}

		// 自动将单词识别率数据写入csv文件
		//tmp_test_isWords := IsWords(finding.Secret)
		//appendToCSV([]string{finding.Secret, strconv.FormatBool(tmp_test_isWords)}, "isWordTest.csv")

		// 如果认为不是凭证，就让他continue；如果检测是凭证，就让他进入
		// `长密码`和`短密码` 分开对待
		// 【短密码】
		if rule.RuleID == "generic-high-checkout-short-secret" {
			// 短密码规则
			finding.Secret = TrimCustomCharacter(finding.Secret)
			entropy := shannonEntropy(finding.Secret)
			finding.Entropy = float32(entropy)
			if rule.Entropy != 0.0 {
				if entropy < rule.Entropy {
					continue
				}
			}

			// 短密码新增字符串升降率匹配，此处会导致top100弱密码被跳过
			UpDownRate := UpAndDownRate(finding.Secret)
			if UpDownRate <= 0.5 {
				continue
			}

			finding.ScoreStrength = PasswordStrengthCheck(finding.Secret)

			if WeakPasswordTop100Detect(finding.Secret) {
				// 弱密码top100检测
				findings = append(findings, finding)
				continue
			}

			if KeyboardWalkDetect(finding.Secret) {
				// 检测到键盘密码，就计入统计
				findings = append(findings, finding)
				continue
			}

			// 此段先根据密码中是否有2项以上内容，来直接过滤一部分非密钥的密码
			var CharacterTypeBoolList []bool
			CharacterTypeTruenum := 0
			CharacterTypeBoolList = append(CharacterTypeBoolList, containsDigit(finding.Secret))
			CharacterTypeBoolList = append(CharacterTypeBoolList, containsSymbol(finding.Secret))
			CharacterTypeBoolList = append(CharacterTypeBoolList, containsCodeUsuallySymbol(finding.Secret))
			CharacterTypeBoolList = append(CharacterTypeBoolList, containsUpCharacter(finding.Secret))
			CharacterTypeBoolList = append(CharacterTypeBoolList, containsDownCharacter(finding.Secret))
			for _, v := range CharacterTypeBoolList {
				if v == true {
					CharacterTypeTruenum++
				}
			}
			// 此段先根据密码中是否有2项以上内容，来直接过滤一部分非密钥的密码
			if CharacterTypeTruenum <= 2 {
				continue
			}

			// 如果密码复杂度不达 3/4 则不计入统计
			if finding.ScoreStrength < 5 {
				continue
			}
		} else if rule.RuleID == "IP address" {
			// 判断是 ipv4 还是 ipv6
			splitedString := strings.Split(finding.Secret, ".")

			fakeIpFlag := false

			if len(splitedString) == 4 {
				//	处理ipv4
				for _, sigmentSplitedString := range splitedString {
					if !DetectIpLegal(sigmentSplitedString) {
						fakeIpFlag = true
					}
				}
			} else {
				//	处理ipv6

			}
			if fakeIpFlag == true {
				continue
			}
		} else if strings.Contains(rule.RuleID, "generic-hash") && containsDigit(finding.Secret) && (containsUpCharacter(finding.Secret) || containsDownCharacter(finding.Secret)) {
			// 计算香农熵
			entropy := shannonEntropy(finding.Secret)
			finding.Entropy = float32(entropy)
			if rule.Entropy != 0.0 {
				if entropy <= rule.Entropy {
					//跳过非允许熵值的地方
					// entropy is too low, skip this finding
					continue
				}
			}
			UpDownRate := UpAndDownRate(finding.Secret)
			if UpDownRate <= 0.4 {
				continue
			} else {
				findings = append(findings, finding)
			}

		} else if rule.RuleID == "private-key" || rule.RuleID == "public-key" {
			certificationFlag := false
			for _, specialCharacter := range []string{"$", "(", ")"} {
				if strings.Contains(finding.Secret, specialCharacter) {
					certificationFlag = true
				}
			}
			if certificationFlag == true {
				continue
			}
		} else {
			// 非特定类型规则 和密码规则

			UpDownRate := UpAndDownRate(finding.Secret)
			if UpDownRate <= 0.4 {
				continue
			}

			// 计算香农熵
			entropy := shannonEntropy(finding.Secret)
			finding.Entropy = float32(entropy)
			if rule.Entropy != 0.0 {
				if entropy <= rule.Entropy {
					//跳过非允许熵值的地方
					// entropy is too low, skip this finding
					continue
				}

				if rule.RuleID == "generic-high-checkout" {
					// 模糊匹配需要比较所在行中是否有关键字内容
					// matchedContent是匹配内容源文件完整的所在行（含多行）
					handled_raw_rows := ReplaceN(fragment.Raw)
					raw_rows := strings.Split(handled_raw_rows, "\n")
					//tmp := raw_rows[finding.StartLine:finding.EndLine]
					//fmt.Println(tmp)
					matchedContent := strings.Join(raw_rows[finding.StartLine:finding.EndLine+1], "\n")
					//fmt.Println(matchedContent)
					// 检测matchedContent中是否包含关键字
					KeywordFlag := false
					for _, single_keyword := range rule.Keywords {
						if strings.Contains(matchedContent, single_keyword) {
							KeywordFlag = true
							break
						}
					}
					if KeywordFlag == false {
						continue
					}

					// 长密码规则
					finding.Secret = TrimCustomCharacter(finding.Secret)
					finding.ScoreStrength = PasswordStrengthCheck(finding.Secret)

					if KeyboardWalkDetect(finding.Secret) {
						// 检测到短密码，就计入统计
						findings = append(findings, finding)
						continue
					}

					// 【高长度密钥计算，大于8位】
					// 这里包含数字才会认为是匹配到的东西，我感觉不太科学，故注释
					//if !containsDigit(secret) {
					//	continue
					//}
					UpDownRate := UpAndDownRate(finding.Secret)
					isWords := IsWords(finding.Secret)

					if UpDownRate <= 0.4 || isWords {
						//if UpDownRate <= 0.4 {
						continue
					}
					if finding.ScoreStrength < 5 {
						continue
					}
				}

			}
		}
		findings = append(findings, finding)
	}
	return findings
}

// GitScan accepts a *gitdiff.File channel which contents a git history generated from
// the output of `git log -p ...`. startGitScan will look at each file (patch) in the history
// and determine if the patch contains any findings.
func (d *Detector) DetectGit(source string, logOpts string, gitScanType GitScanType) ([]report.Finding, error) {
	// git log 扫描的地方
	var (
		gitdiffFiles <-chan *gitdiff.File
		err          error
	)
	switch gitScanType {
	case DetectType:
		gitdiffFiles, err = git.GitLog(source, logOpts)
		if err != nil {
			return d.findings, err
		}
	case ProtectType:
		gitdiffFiles, err = git.GitDiff(source, false)
		if err != nil {
			return d.findings, err
		}
	case ProtectStagedType:
		gitdiffFiles, err = git.GitDiff(source, true)
		if err != nil {
			return d.findings, err
		}
	}
	// 线程修改至1000
	s := semgroup.NewGroup(context.Background(), 1000)

	for gitdiffFile := range gitdiffFiles {
		gitdiffFile := gitdiffFile

		// skip binary files
		if gitdiffFile.IsBinary || gitdiffFile.IsDelete {
			continue
		}

		// Check if commit is allowed
		commitSHA := ""
		if gitdiffFile.PatchHeader != nil {
			commitSHA = gitdiffFile.PatchHeader.SHA
			if d.Config.Allowlist.CommitAllowed(gitdiffFile.PatchHeader.SHA) {
				continue
			}
		}
		d.addCommit(commitSHA)

		s.Go(func() error {
			for _, textFragment := range gitdiffFile.TextFragments {
				// 对过于大的文件进行放过，与no-git扫的地方限制文件大小为2MB的原理类似，比如这里设置大于12000不进行扫描
				// 说明一下，写在用户手册
				if textFragment == nil || len(textFragment.Lines) > 90000 {
					return nil
				}

				fragment := Fragment{
					Raw:       textFragment.Raw(gitdiff.OpAdd),
					CommitSHA: commitSHA,
					FilePath:  gitdiffFile.NewName,
				}

				for _, finding := range d.Detect(fragment) {
					d.addFinding(augmentGitFinding(finding, textFragment, gitdiffFile))
				}
			}
			return nil
		})
	}

	if err := s.Wait(); err != nil {
		return d.findings, err
	}
	log.Debug().Msgf("%d commits scanned. Note: this number might be smaller than expected due to commits with no additions", len(d.commitMap))
	return d.findings, nil
}

// DetectFiles accepts a path to a source directory or file and begins a scan of the
// file or directory.
func (d *Detector) DetectFiles(source string) ([]report.Finding, error) {
	// no-git 的地方
	// 线程修改至1000
	s := semgroup.NewGroup(context.Background(), 1000)
	paths := make(chan string)
	s.Go(func() error {
		defer close(paths)
		return filepath.Walk(source,
			func(path string, fInfo os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if fInfo.Name() == ".git" && fInfo.IsDir() {
					return filepath.SkipDir
				}
				//我在这里进行了修改
				//下面可以匹配不想进行匹配的文件名的正则表达式，这里本来是不匹配 .gitignore 中表明的文件名字
				TargetFileNameExp := regexp.MustCompile(`\.gitignore`)
				//下面进行文件名正则匹配和文件大小的选择性不检测，避免卡死
				// 比如，大于2MB的文件选择不扫描
				if fInfo.Mode().IsRegular() && !TargetFileNameExp.MatchString(fInfo.Name()) && fInfo.Size() < 4*1024*1024 {
					paths <- path
				}
				return nil
			})
	})

	for pa := range paths {
		// 从这里开始传入文件，`paths`是多个文件，`pa`和`p`是 单个文件

		p := pa
		s.Go(func() error {
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}

			mimetype, err := filetype.Match(b)
			if err != nil {
				return err
			}
			if mimetype.MIME.Type == "application" {
				return nil // skip binary files
			}

			relativePath, _ := filepath.Rel(source, p)
			relativePath = filepath.ToSlash(relativePath)

			fragment := Fragment{
				Raw:      string(b),
				FilePath: relativePath,
			}
			// 传入整个文件，然后d.Detect()函数处理后，返回多个值
			for _, finding := range d.Detect(fragment) {
				// need to add 1 since line counting starts at 1
				finding.EndLine++
				finding.StartLine++
				d.addFinding(finding)
			}

			return nil
		})

	}

	if err := s.Wait(); err != nil {
		return d.findings, err
	}
	// 直接返回给 cmd/detect.go 的最终结果就是 findings
	return d.findings, nil
}

// Detect scans the given fragment and returns a list of findings
// DetectGit() 和 DetectFiles() 都会调用这里
func (d *Detector) Detect(fragment Fragment) []report.Finding {
	// fragment是整个文件内容

	var findings []report.Finding

	// initiate fragment keywords
	// 注意fragment.keywords是一个map
	fragment.keywords = make(map[string]bool)

	// check if filepath is allowed
	// 此处的d.Comfig.Allowlist.PathAllowed()是检查`后缀名`是否可以`允许忽略`
	// 如果发现被检测文件是`忽略后缀的文件`或`config.toml这种规则配置文件`就直接return，不进行检测
	if fragment.FilePath != "" && (d.Config.Allowlist.PathAllowed(fragment.FilePath) ||
		fragment.FilePath == d.Config.Path) {
		return findings
	}

	// add newline indices for location calculation in detectRule
	fragment.newlineIndices = regexp.MustCompile("\n").FindAllStringIndex(fragment.Raw, -1)

	// build keyword map for prefiltering rules
	// 此处行为是将文件内容分行，然后检测每行是否有关键字
	normalizedRaw := strings.ToLower(fragment.Raw)
	//  先利用AC自动机(ahocorasick.AhoCorasick) 提炼出多个关键字，随后会和 [[rule]] 中的关键字比较，来看要不要进行匹配
	// 不清楚这里是为了快速检出什么，我看下面循环里是 password 字符串
	// 这里传入文件的源码，然后，matches 是特定算法返回的多个值，然后给了map

	// matches是AC自动机识别后的keyword
	// fragment.keywords 存入 AC自动机识别到的关键字，以 map[string]bool 结构存储
	matches := d.prefilter.FindAll(normalizedRaw)
	for _, m := range matches {
		// 如果要看AC自动机对此文件识别出什么，则放开下面的注释可以看到内容
		// fmt.Println(normalizedRaw[m.Start():m.End()])
		fragment.keywords[normalizedRaw[m.Start():m.End()]] = true
	}

	// 这里进行[[rule]]遍历，进行规则匹配，检测到关键字就把`行`加入findings
	for _, rule := range d.Config.Rules {
		if len(rule.Keywords) == 0 {
			// if not keywords are associated with the rule always scan the fragment using the rule
			// [[rule]]中如果没有关键字，就直接检测然后返回
			findings = append(findings, d.detectRule(fragment, rule)...)
		} else {
			fragmentContainsKeyword := false
			// check if keywords are in the fragment
			for _, rk := range rule.Keywords {
				if _, ok := fragment.keywords[strings.ToLower(rk)]; ok {
					fragmentContainsKeyword = true
					break
				}
			}

			// 代码触发rule的关键字，就存入待匹配规则及数据
			if fragmentContainsKeyword {
				findings = append(findings, d.detectRule(fragment, rule)...)
			}
		}
	}
	return filter(findings, d.Redact)
}

// addFinding synchronously adds a finding to the findings slice
func (d *Detector) addFinding(finding report.Finding) {
	// check if we should ignore this finding
	if _, ok := d.secretDetectionIgnore[finding.Fingerprint]; ok {
		log.Debug().Msgf("ignoring finding with Fingerprint %s",
			finding.Fingerprint)
		return
	}

	d.findingMutex.Lock()
	d.findings = append(d.findings, finding)
	if d.Verbose {
		printFinding(finding)
	}
	d.findingMutex.Unlock()
}

// addCommit synchronously adds a commit to the commit slice
func (d *Detector) addCommit(commit string) {
	d.commitMap[commit] = true
}
