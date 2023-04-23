go build -ldflags "-s -w"
set GOOS=linux
set GOARCH=amd64
go build -ldflags "-s -w"
