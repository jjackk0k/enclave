#!/bin/sh
set -e
mkdir -p /out
GOOS=linux   GOARCH=amd64 go build -o /out/portcheck-linux .
GOOS=windows GOARCH=amd64 go build -o /out/portcheck-windows.exe .
L=$(stat -c%s /out/portcheck-linux)
W=$(stat -c%s /out/portcheck-windows.exe)
LM=$(head -c4 /out/portcheck-linux       | od -An -tx1 | tr -d ' \n')
WM=$(head -c2 /out/portcheck-windows.exe | od -An -tx1 | tr -d ' \n')
echo "RESULT:{\"linuxBytes\":$L,\"windowsBytes\":$W,\"linuxMagic\":\"$LM\",\"windowsMagic\":\"$WM\"}"
