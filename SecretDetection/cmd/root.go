package cmd

import (
	"SecretDetection/bindata"
	"bytes"
	"fmt"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"os"
	"strings"
)

const banner = `
   _____                    _   _____       _            _   _             
  / ____|                  | | |  __ \     | |          | | (_)            
 | (___   ___  ___ _ __ ___| |_| |  | | ___| |_ ___  ___| |_ _  ___  _ __  
  \___ \ / _ \/ __| '__/ _ \ __| |  | |/ _ \ __/ _ \/ __| __| |/ _ \| '_ \ 
  ____) |  __/ (__| | |  __/ |_| |__| |  __/ ||  __/ (__| |_| | (_) | | | |
 |_____/ \___|\___|_|  \___|\__|_____/ \___|\__\___|\___|\__|_|\___/|_| |_|
`

const configDescription = `配置规则的方法
	--config/-c
如果没有进行规则配置，则使用程序内置的规则
`

var rootCmd = &cobra.Command{
	Use:   "SecretDetection",
	Short: "SecretDetection的凭证扫描",
}

func init() {
	cobra.OnInitialize(initLog)
	rootCmd.CompletionOptions.DisableDefaultCmd = true
	rootCmd.PersistentFlags().StringP("config", "c", "", "指定自定义的规则配置文件")
	rootCmd.PersistentFlags().MarkHidden("config")
	// MarkHidden函数，隐藏config配置项
	rootCmd.PersistentFlags().Int("exit-code", 1, "扫描到凭证数量非0时的退出码")
	rootCmd.PersistentFlags().StringP("source", "s", ".", "待扫描代码的目录")
	rootCmd.PersistentFlags().StringP("report-path", "r", "", "扫描结果文件命名")
	rootCmd.PersistentFlags().StringP("report-format", "f", "json", "扫描结果文件格式 (json, csv, sarif)")
	rootCmd.PersistentFlags().StringP("log-level", "l", "info", "日志等级 (trace, debug, info, warn, error, fatal)")
	rootCmd.PersistentFlags().BoolP("verbose", "v", true, "详情")
	rootCmd.PersistentFlags().Bool("redact", false, "--redact 遮挡输出的凭证信息")
	err := viper.BindPFlag("config", rootCmd.PersistentFlags().Lookup("config"))
	if err != nil {
		log.Fatal().Msgf("err binding config %s", err.Error())
	}
}

func initLog() {
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	ll, err := rootCmd.Flags().GetString("log-level")
	if err != nil {
		log.Fatal().Msg(err.Error())
	}
	switch strings.ToLower(ll) {
	case "trace":
		zerolog.SetGlobalLevel(zerolog.TraceLevel)
	case "debug":
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	case "info":
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	case "warn":
		zerolog.SetGlobalLevel(zerolog.WarnLevel)
	case "err", "error":
		zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	case "fatal":
		zerolog.SetGlobalLevel(zerolog.FatalLevel)
	default:
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}
}

func initConfig() {
	fmt.Fprint(os.Stderr, banner)
	cfgPath, err := rootCmd.Flags().GetString("config")
	if err != nil {
		log.Fatal().Msg(err.Error())
	}
	// 下面的if else if else 是进行viper的配置文件的配置
	// 结束了if else if else 后的err := viper.ReadInConfig()才是配置文件的读取
	if cfgPath != "" {

		bindata_default_toml, _ := bindata.Asset("default.toml")
		viper.SetConfigType("toml")
		if err := viper.ReadConfig(bytes.NewBuffer(bindata_default_toml)); err != nil {
			log.Fatal().Msgf("unable to load config, err: %s", err)
		}

		// configs: 读取默认配置文件
		configs := viper.AllSettings()
		// user_custom_configs: 读取用户自定义规则
		viper.SetConfigFile(cfgPath)
		if err := viper.ReadInConfig(); err != nil {
			log.Fatal().Msgf("unable to load config, err: %s", err)
		}
		user_custom_configs := viper.AllSettings()

		// 处理[[rules]] 开始
		if user_custom_configs["rules"] != nil {
			config_rules := configs["rules"].([]interface{})
			user_custom_configs_rules := user_custom_configs["rules"].([]interface{})

			var NEW_RULE_FLAG bool
			// NEW_ADD_FLAG 检测是否是用户的新的规则集（且默认规则没有改规则集），要进行rule添加处理
			for user_custom_configs_rules_i, user_custom_configs_rules_v := range user_custom_configs_rules {
				NEW_RULE_FLAG = true
				for tmp_config_i, tmp_config_v := range config_rules {
					if tmp_config_v.(map[string]interface{})["id"] == user_custom_configs_rules_v.(map[string]interface{})["id"] {
						config_rules[tmp_config_i] = user_custom_configs_rules[user_custom_configs_rules_i]
						NEW_RULE_FLAG = false
						break
					}
				}
				// NEW_RULE_FLAG == true 意味着默认规则的rules不存在新的id规则
				if NEW_RULE_FLAG == true {
					config_rules = append(config_rules, user_custom_configs_rules_v)
				}
			}

			configs["rules"] = config_rules
		}
		// 处理[[rules]] 结束

		// 处理[allowlist] 开始
		if user_custom_configs["allowlist"] != nil {
			var tmpConfigAllowlist map[string]interface{}
			tmpConfigAllowlist = make(map[string]interface{})
			for k, v := range configs["allowlist"].(map[string]interface{}) {
				tmpConfigAllowlist[k] = v
				//fmt.Println(k)
				//fmt.Println(v)
			}
			user_custom_configs_allowlist := user_custom_configs["allowlist"].(map[string]interface{})
			for k, v := range user_custom_configs_allowlist {
				if k == "paths" {
					tmpConfigAllowlist[k] = v
				}
			}
			configs["allowlist"] = tmpConfigAllowlist

		}
		// 处理[allowlist] 结束

		for k, v := range configs {
			viper.Set(k, v)
		}
	} else {

		bindata_default_toml, _ := bindata.Asset("default.toml")
		viper.SetConfigType("toml")
		if err := viper.ReadConfig(bytes.NewBuffer(bindata_default_toml)); err != nil {
			log.Fatal().Msgf("unable to load config, err: %s", err)
		}
	}
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		if strings.Contains(err.Error(), "unknown flag") {
			// exit code 126: Command invoked cannot execute
			os.Exit(126)
		}
		log.Fatal().Msg(err.Error())
	}
}
