@ECHO OFF

pushd ..
CALL :cleanprojdir libnetcrypt
CALL :cleanprojdir libtommath
CALL :cleanprojdir testprog
CALL :cleanprojdir bin

IF EXIST ipch rd /q /s ipch
IF EXIST libnetcrypt.sdf del /q libnetcrypt.sdf
IF EXIST libnetcrypt.suo (
	ATTRIB -h libnetcrypt.suo
	DEL /q libnetcrypt.suo
)

EXIT /B 0

:cleanprojdir
SETLOCAL

ECHO Cleaning %1

PUSHD %1
CALL :delstarifexist *.user
IF EXIST win32 rd /q /s win32
IF EXIST x64 rd /q /s x64
POPD

ENDLOCAL
EXIT /B

:delstarifexist
SETLOCAL

FOR %%F IN ("%1") DO (
	DEL /q "%%~nxF"
)

ENDLOCAL
EXIT /B