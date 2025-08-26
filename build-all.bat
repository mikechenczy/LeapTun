del /Q ".\app.syso"
SET GOOS=linux
SET GOARCH=amd64
go build -a -trimpath -asmflags "-s -w" -ldflags "-s -w -buildid=" -o "build\linux\LeapTun_amd64"
SET GOOS=linux
SET GOARCH=arm64
go build -a -trimpath -asmflags "-s -w" -ldflags "-s -w -buildid=" -o "build\linux\LeapTun_arm64"
copy /Y "windows\app.syso" "."
SET GOOS=windows
SET GOARCH=amd64
go build -a -trimpath -asmflags "-s -w" -ldflags "-s -w -buildid=" -o "build\windows\LeapTun_amd64.exe"
pause
