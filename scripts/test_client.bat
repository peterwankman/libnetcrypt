@echo off

ECHO ARCH = %1
ECHO CONF = %2

IF [%ARCH%] == [] SET ARCH = x64
IF [%CONF%] == [] SET CONF = debug

SET ARCH=%1
SET CONF=%2

IF NOT [%3] == [] (
	ECHO KEY = %3
	ECHO.
	bin\%ARCH%\%CONF%\testprog.exe -c localhost -p 1056 -k %3
	EXIT /b 0
)

ECHO.

bin\%ARCH%\%CONF%\testprog.exe -c localhost -p 1056 %KEY%