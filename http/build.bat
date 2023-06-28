go-bindata.exe -pkg config -o config/SecretDetection_rules.go config/default.toml


go build  -ldflags "-w -s"  -o http.exe
set GOOS=linux
set GOARCH=amd64
go build -ldflags "-w -s" -o http
