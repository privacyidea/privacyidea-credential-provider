@echo on

set PROJECT_HOST=192.168.1.3

set PROJECT_NAME=PrivacyIDEA-CredentialProvider
set TARGET_NAME=PrivacyIDEACredentialProvider

set SETUP_PATH=WiXSetup\bin\x86\Debug\en-us\%TARGET_NAME%Setup.msi
set PDB_PATH=CredentialProvider\bin\Win32\Debug\CredentialProvider.pdb

set SETUP_CONF= 

set BASE_SHARE=\\%PROJECT_HOST%\Source\Repos
set SHARE_VOLUME=X:

net use %SHARE_VOLUME% %BASE_SHARE%\%PROJECT_NAME%

cd %SHARE_VOLUME%

kill msiexec.exe
kill TrustedInstaller.exe

REM msiexec /x %SHARE_VOLUME%\%SETUP_PATH% /q
msiexec /lxv c:\%PROJECT_NAME%_install.log /i %SHARE_VOLUME%\%SETUP_PATH% /q AGREETOLICENSE="yes" %SETUP_CONF% 

copy %SHARE_VOLUME%\%PDB_PATH% C:\Windows\System32\

copy %SHARE_VOLUME%\symbols\* C:\Windows\System32\

gflags.exe -p /enable LogonUI.exe /full

net use %SHARE_VOLUME% /DELETE

pause