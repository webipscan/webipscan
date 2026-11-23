@REM ###################################################### 
@REM 可选默认使用utf-8 
@REM chcp 65001
@REM ###################################################### 
@cls && echo off &&echo PAN:"%~d0" CD:"%~dp0" FILE:"%~f0"
@cd /d %~dp0 && echo CD:"%cd%" 
@REM ###################################################### 
@REM echo 倒计时10秒后退出 && for /L %%i in (1 1 10) do set /p a=■<nul&ping /n 2 -w 100 127.0.0.1>nul
@REM ###################################################### 
@REM #https://ghfast.top/https://github.com/v2fly/geoip/releases/latest/download/geoip.dat
@REM #https://gh-proxy.com/https://github.com/v2fly/geoip/releases/latest/download/geoip.dat
@REM ###################################################### 
@REM aria2c.exe --enable-rpc=true --rpc-allow-origin-all=true  --rpc-listen-port=6800 --conf-path=./aria2.conf --dir=../../vhost/web_down  
@REM aria2c.exe --enable-rpc=true --rpc-allow-origin-all=true  --rpc-listen-port=6800 --dir=./aria2c/ --save-session-interval=20 --save-session=./.aria2c/.session
@REM https://gh-proxy.com/github.com/aria2/aria2/releases/download/release-1.37.0/aria2-1.37.0-win-64bit-build1.zip
@REM ###################################################### 
REM go install github.com/tc-hib/go-winres@latest
REM go-winres make
@REM ###################################################### 
@REM go build -ldflags="-s -w"  && dir && webipscan.exe -d --url http://127.0.0.1:9100
@REM go build -ldflags="-s -w"  && dir && webipscan.exe -d --url http://127.0.0.1:9100
REM go build -ldflags="-s -w"  && dir && webipscan --user -d --url http://127.0.0.1:9801
REM go build -ldflags="-s -w"  && dir && webipscan --user -d 
go build -ldflags="-s -w"  && dir && webipscan --user -d  demo.mp4

