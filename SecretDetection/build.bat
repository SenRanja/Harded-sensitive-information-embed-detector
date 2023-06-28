go build  -ldflags "-w -s"  -o SecretDetection.exe
set GOOS=linux
set GOARCH=amd64
go build -ldflags "-w -s" -o SecretDetection

