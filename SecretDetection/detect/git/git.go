package git

import (
	"bufio"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/gitleaks/go-gitdiff/gitdiff"
	"github.com/rs/zerolog/log"
)

// GitLog returns a channel of gitdiff.File objects from the
// git log -p command for the given source.
func GitLog(source string, logOpts string) (<-chan *gitdiff.File, error) {
	sourceClean := filepath.Clean(source)
	var cmd *exec.Cmd
	if logOpts != "" {
		args := []string{"-C", sourceClean, "log", "-p", "-U0"}
		args = append(args, strings.Split(logOpts, " ")...)
		cmd = exec.Command("git", args...)
	} else {
		cmd = exec.Command("git", "-C", sourceClean, "log", "-p", "-U0", "--full-history", "--all")
		//cmd = exec.Command("git", "-C", sourceClean, "log", "-p", "-1", "-U0", "--full-history", "--all")
	}

	log.Debug().Msgf("executing: %s", cmd.String())

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	//stdout_data, _ := ioutil.ReadAll(stdout)
	//stderr_data, _ := ioutil.ReadAll(stderr)
	//stdout_filePath := "E:\\BiLing\\20220905-gitleaks-Docker\\SecretDetection\\stdout.txt"
	//stderr_filePath := "E:\\BiLing\\20220905-gitleaks-Docker\\SecretDetection\\stderr.txt"
	//stdout_file, err := os.OpenFile(stdout_filePath, os.O_WRONLY|os.O_CREATE, 0666)
	//stderr_file, err := os.OpenFile(stderr_filePath, os.O_WRONLY|os.O_CREATE, 0666)
	//defer stdout_file.Close()
	//defer stderr_file.Close()
	//
	//fileWriter := bufio.NewWriter(stdout_file)
	//fileWriter.Write(stdout_data)
	//
	//fileWriter = bufio.NewWriter(stderr_file)
	//fileWriter.Write(stderr_data)

	go listenForStdErr(stderr)
	time.Sleep(50 * time.Millisecond)

	return gitdiff.Parse(stdout)
}

// GitDiff returns a channel of gitdiff.File objects from
// the git diff command for the given source.
func GitDiff(source string, staged bool) (<-chan *gitdiff.File, error) {
	sourceClean := filepath.Clean(source)
	var cmd *exec.Cmd
	cmd = exec.Command("git", "-C", sourceClean, "diff", "-U0", ".")
	if staged {
		cmd = exec.Command("git", "-C", sourceClean, "diff", "-U0",
			"--staged", ".")
	}
	log.Debug().Msgf("executing: %s", cmd.String())

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	go listenForStdErr(stderr)
	time.Sleep(50 * time.Millisecond)

	return gitdiff.Parse(stdout)
}

// listenForStdErr listens for stderr output from git and prints it to stdout
// then exits with exit code 1
func listenForStdErr(stderr io.ReadCloser) {
	scanner := bufio.NewScanner(stderr)
	errEncountered := false
	for scanner.Scan() {
		if strings.Contains(scanner.Text(),
			"exhaustive rename detection was skipped") ||
			strings.Contains(scanner.Text(),
				"inexact rename detection was skipped") ||
			strings.Contains(scanner.Text(),
				"you may want to set your diff.renameLimit") {

			// 2022-11-3 我处理此处，停止了报错的显示
			//log.Warn().Msg(scanner.Text())
		} else {
			// 此处会出现git log 命令的报错，与程序无关
			// 2022-11-3 我处理此处，停止了报错的显示
			// 不太好处理git本身的报错
			//log.Error().Msg(scanner.Text())
			//errEncountered = true
		}
	}
	if errEncountered {
		os.Exit(1)
	}
}
