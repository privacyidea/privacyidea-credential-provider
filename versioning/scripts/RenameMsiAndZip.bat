@echo off

REM capture script output in variable
for /f "usebackq tokens=*" %%a in (`cscript "%~dp0\getmsiversion.vbs" "%~f1"`) do (set myvar=%%a)

SET MSIPATH=%~dp1
SET MSINAME=%~n1-%myvar%-%~2%~x1
echo Renaming "%1" to "%MSIPATH%%MSINAME%"
move /Y "%1" "%MSIPATH%%MSINAME%"

SET MSITMP=%TMP%\%MSINAME%
echo Copying MSI to tmp location "%MSITMP%"
copy "%MSIPATH%%MSINAME%" "%MSITMP%"

SET ZIPTMP=%TMP%\zip.exe
echo Copying zip.exe to tmp location "%ZIPTMP%"
copy "%~dp0\zip.exe" "%ZIPTMP%"

echo Changing directory to tmp location "%TMP%"
cd /d "%TMP%"
echo %cd%

SET ZIPNAME=%~dp1%~n1-%myvar%-%~2.zip
echo Archiving "%MSINAME%" in "%ZIPNAME%"
"%ZIPTMP%" -D "%ZIPNAME%" "%MSINAME%"

echo Deleting tmp files
del "%MSITMP%"
del "%ZIPTMP%"

REM TODO: Only link when debugging
SET LINKNAME=%~dp1%~n1%~x1
echo Creating link "%LINKNAME%" to "%MSIPATH%%MSINAME%"
del "%LINKNAME%"
mklink /H "%LINKNAME%" "%MSIPATH%%MSINAME%"
