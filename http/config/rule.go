package config

import (
	"encoding/json"
	"fmt"
	"github.com/spf13/viper"
	"regexp"
)

type ViperConfig struct {
	Description string
	Extend      Extend
	Rules       []struct {
		ID          string
		Description string
		Entropy     float64
		SecretGroup int
		Regex       string
		Keywords    []string
		Path        string
		Tags        []string

		Allowlist struct {
			Regexes   []string
			Paths     []string
			Commits   []string
			StopWords []string
		}
	}
	Allowlist struct {
		Regexes   []string
		Paths     []string
		Commits   []string
		StopWords []string
	}
}

type Extend struct {
	Path       string
	URL        string
	UseDefault bool
}

type Rule struct {
	// Description is the description of the rule.
	Description string

	// RuleID is a unique identifier for this rule
	RuleID string

	// Entropy is a float representing the minimum shannon
	// entropy a regex group must have to be considered a secret.
	Entropy float64

	// SecretGroup is an int used to extract secret from regex
	// match and used as the group that will have its entropy
	// checked if `entropy` is set.
	SecretGroup int

	// Regex is a golang regular expression used to detect secrets.
	Regex *regexp.Regexp

	// Path is a golang regular expression used to
	// filter secrets by path
	Path *regexp.Regexp

	// Tags is an array of strings used for metadata
	// and reporting purposes.
	Tags []string

	// Keywords are used for pre-regex check filtering. Rules that contain
	// keywords will perform a quick string compare check to make sure the
	// keyword(s) are in the content being scanned.
	Keywords []string

	// Allowlist allows a rule to be ignored for specific
	// regexes, paths, and/or commits
	Allowlist Allowlist
}

type Allowlist struct {
	// Short human readable description of the allowlist.
	Description string

	// Regexes is slice of content regular expressions that are allowed to be ignored.
	Regexes []*regexp.Regexp

	// Paths is a slice of path regular expressions that are allowed to be ignored.
	Paths []*regexp.Regexp

	// Commits is a slice of commit SHAs that are allowed to be ignored.
	Commits []string

	// StopWords is a slice of stop words that are allowed to be ignored.
	// This targets the _secret_, not the content of the regex match like the
	// Regexes slice.
	StopWords []string
}

func RuleJson(TomlRuleFilename string) ([]byte, error) {

	viper.SetConfigName(TomlRuleFilename)
	viper.SetConfigType("toml")
	viper.AddConfigPath("./config/")
	err := viper.ReadInConfig()
	if err != nil {
		panic(err.Error())
	}
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// Config file not found; ignore error if desired
			fmt.Printf("%s文件没有找到", TomlRuleFilename)
		} else {
			// Config file was found but another error was produced
		}
	}
	var vc ViperConfig
	err = viper.Unmarshal(&vc)
	if err != nil {
		panic(err)
	}
	b, err := json.Marshal(vc)
	//fmt.Println(string(b))
	return b, err
}
