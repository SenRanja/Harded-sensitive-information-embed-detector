package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"SecretDetection/config"
	"SecretDetection/detect"
	"SecretDetection/report"
)

func init() {
	rootCmd.AddCommand(detectCmd)
	detectCmd.Flags().String("log-opts", "", "使用git log选项进行过滤")
	//detectCmd.Flags().Bool("no-git", false, "不进行git log扫描。即要扫描的目标文件非git仓库（目录中没有.git目录）时添加该选项")
}

var detectCmd = &cobra.Command{
	Use:   "detect",
	Short: "扫描代码中的硬编码",
	Run:   runDetect,
}

func runDetect(cmd *cobra.Command, args []string) {
	initConfig()
	var (
		vc       config.ViperConfig
		findings []report.Finding
		err      error
	)

	// Load config
	if err = viper.Unmarshal(&vc); err != nil {
		log.Fatal().Err(err).Msg("Failed to load config")
	}
	cfg, err := vc.Translate()
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to load config")
	}

	cfg.Path, _ = cmd.Flags().GetString("config")

	// start timer
	start := time.Now()

	// Setup detector
	detector := detect.NewDetector(cfg)

	// 此处放置规则集
	detector.Config.Path, err = cmd.Flags().GetString("config")
	if err != nil {
		log.Fatal().Err(err)
	}
	source, err := cmd.Flags().GetString("source")
	if err != nil {
		log.Fatal().Err(err)
	}

	// set verbose flag
	if detector.Verbose, err = cmd.Flags().GetBool("verbose"); err != nil {
		log.Fatal().Err(err)
	}
	// set redact flag
	if detector.Redact, err = cmd.Flags().GetBool("redact"); err != nil {
		log.Fatal().Err(err)
	}

	// set exit code
	exitCode, err := cmd.Flags().GetInt("exit-code")
	if err != nil {
		log.Fatal().Err(err)
	}

	var noGit bool
	_, err = os.Stat(filepath.Join(source, ".git"))
	if os.IsNotExist(err) {
		noGit = true
	}

	noGit, _ = cmd.Flags().GetBool("no-git")

	// start the detector scan
	if noGit {
		fmt.Println("[#] 检测扫描模式为no-git")
		findings, err = detector.DetectFiles(source)
		if err != nil {
			// don't exit on error, just log it
			log.Error().Err(err)
		}

	} else {
		fmt.Println("[#] 检测到环境是git仓库目录，开始检测。注意需要主机本身安装有git工具。")
		logOpts, err := cmd.Flags().GetString("log-opts")
		if err != nil {
			log.Fatal().Err(err)
		}
		findings, err = detector.DetectGit(source, logOpts, detect.DetectType)
		if err != nil {
			// don't exit on error, just log it
			log.Error().Err(err)
		}
	}

	// log info about the scan
	log.Info().Msgf("扫描用时: %s", time.Since(start))
	if len(findings) != 0 {
		log.Warn().Msgf("发现凭证泄露数量: %d", len(findings))
	} else {
		log.Info().Msg("未发现泄露的凭证")
	}

	// write report if desired
	reportPath, _ := cmd.Flags().GetString("report-path")
	ext, _ := cmd.Flags().GetString("report-format")
	if reportPath != "" {
		if err = report.Write(findings, cfg, ext, reportPath, noGit); err != nil {
			log.Fatal().Err(err)
		}
	}

	if len(findings) != 0 {
		os.Exit(exitCode)
	}
}
