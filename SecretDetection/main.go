package main

import (
	"os"
	"os/signal"

	"SecretDetection/cmd"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	// send all logs to stdout
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, os.Interrupt)
	go listenForInterrupt(stopChan)

	cmd.Execute()
}

func listenForInterrupt(stopScan chan os.Signal) {
	<-stopScan
	log.Fatal().Msg("检测到 Ctrl+C 中断执行")
}
