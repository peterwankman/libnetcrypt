@echo off

ECHO ARCH = %1
ECHO CONF = %2

IF [%1] == [] EXIT /b 0
IF [%2] == [] EXIT /b 0

SET ARCH=%1
SET CONF=%2

ECHO.
ECHO Running...

bin\%ARCH%\%CONF%\testprog.exe -l -p 1056 -k key_server.txt