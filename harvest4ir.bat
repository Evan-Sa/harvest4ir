@echo off
:: 
:: This script collect some artefact for live response.
::
:: Want to involve to this code ?
::
::
:: #### 			IMPORTANT
:: When you add a new tools, you have to put the architecture 32 or 64 just before ".exe"
::
::
:: Each line is logged in the file "actions.log" and almost each errors in "errors.log"
:: Only embedded tools are use to prevent DLL hijack or other thing to hide real results (even CMD.EXE)
:: For that, use the var %tools% to launch your command and put the executable name after.
:: After the executable name, put the var %arch%.
::
::
:: The %_line% variable store the command. It is used to pass a parameter to the function :log_actions
:: This function will log the command in actions.log and check if an error occurred and put it in errors.log
:: Each command need two more line (every time !!) first, store the command in the var _line and after the command launch, call the function log_actions
::



:: --------------------------------------------------------------------------------------------------------------------------
::	Variables declaration
:: --------------------------------------------------------------------------------------------------------------------------
::
:: Determining the operating system since file paths between XP/2003/2000 and 7/2008 are different

ver|find /C "version 5"
if %ERRORLEVEL% == 0 set os=legacy
REM For XP, using the old short path
set _path=%~s0
set _path=%_path:~0,-12%
:: --------------------------------------------------------------------------------------------------------------------------
:: Variable depending of the OS
:: --------------------------------------------------------------------------------------------------------------------------
if %os% == legacy (
	REM Events logs
	set event_path=%WINDIR%\System32\config\
	set application=AppEvent.evt
	set system=SysEvent.evt
	set security=SecEvent.evt
) else (
	set _path=%~dp0
	REM Events logs
	set event_path=%WINDIR%\System32\winevt\Logs\
	set application=Application.evtx
	set system=System.evtx
	set security=Security.evtx
)

REM Timestamp creation
call ::timestamp
set archive=%COMPUTERNAME%_%timestamp%
set location=%_path%%archive%
REM logs location
set actions=%location%\actions.log
set errors=%location%\errors.log

:main

:: --------------------------------------------------------------------------------------------------------------------------
:: Computer's data collecting
:: --------------------------------------------------------------------------------------------------------------------------
:: Determining the System Architecture
if "%PROCESSOR_ARCHITECTURE%" == "x86" set arch=32
if "%PROCESSOR_ARCHITECTURE%" == "AMD64" set arch=64

REM Till now, only use %_cmd% versus cmd.exe (local one)
set _cmd=%_path%tools\cmd%arch%.exe /C
REM Path to the embedded tools
set tools=%_cmd% %_path%tools\

if not exist %location% (
	REM Location creation
	%tools%mkdir.exe %location%

	REM Creation of the collection log
	cls
	echo ****************************************************************************************** > %actions%
	echo %~0 >> %actions%
	echo Collection Log for Case %COMPUTERNAME% >> %actions%
	echo Log Created at %timestamp% >> %actions%
	echo ****************************************************************************************** >> %actions%
	echo ****************************************************************************************** > %errors%
	echo Error Log for Case %COMPUTERNAME% >> %actions%
	echo Error log Created at %timestamp% >> %errors%
	echo ****************************************************************************************** >> %errors%
	echo Error logs location : %errors% >> %actions%
	echo Computer information : >> %actions%
	ver >> %actions%
	echo Processor architecture : %arch% >> %actions%
	echo. >> %actions%
	echo Partition information >> %actions%
	
	set _line="%tools%wmic%arch% logicaldisk get Description,DriveType,FileSystem,FreeSpace,Name,Size,VolumeName,VolumeSerialNumber | %tools%grep 3"
	%tools%wmic%arch% logicaldisk get Description,DriveType,FileSystem,FreeSpace,Name,Size,VolumeName,VolumeSerialNumber | %tools%grep 3 >> %actions%
	call :log_actions
	call :check_Permissions
	echo. >> %actions%
	echo __________________________________________________________________________________________ >> %actions%
	
	REM Volatile location
	set _line="%tools%mkdir.exe %location%\volatiles"
	%tools%mkdir.exe %location%\volatiles
	call :log_actions
	
	:: Be carreful. winpmem is usally detect as a malware...

	echo Memory dump - First thing to do...  >> %actions%
	set _line="%tools%winpmem.exe %location%\volatiles\physicaldump.bin"
	%tools%winpmem.exe %location%\volatiles\physicaldump.bin
	call :log_actions
	
	echo. >> %actions%
	echo .................................................................................................... >> %actions%
	echo 						Creation of folder for volatile data >> %actions%
	echo .................................................................................................... >> %actions%
	echo. >> %actions%
	set _line="%tools%mkdir.exe %location%\volatiles\processes"
	%tools%mkdir.exe %location%\volatiles\processes
	call :log_actions
	
	set _line="%tools%mkdir.exe %location%\volatiles\processes\dumps"
	%tools%mkdir.exe %location%\volatiles\processes\dumps
	call :log_actions
	
	set _line="%tools%mkdir.exe %location%\volatiles\network"
	%tools%mkdir.exe %location%\volatiles\network
	call :log_actions
	
	set _line="%tools%mkdir.exe %location%\volatiles\misc"
	%tools%mkdir.exe %location%\volatiles\misc
	call :log_actions	
	
	echo. >> %actions%
	echo .................................................................................................... >> %actions%
	echo 					Creation of folder for non volatile data >> %actions%
	echo .................................................................................................... >> %actions%
	echo. >> %actions%
	set _line="%tools%mkdir.exe %location%\non-volatiles"
	%tools%mkdir.exe %location%\non-volatiles
	call :log_actions	
	
	set _line="%tools%mkdir.exe %location%\non-volatiles\registry"
	%tools%mkdir.exe %location%\non-volatiles\registry
	call :log_actions
	
	set _line="%tools%mkdir.exe %location%\non-volatiles\events"
	%tools%mkdir.exe %location%\non-volatiles\events
	call :log_actions
	
	set _line="%tools%mkdir.exe %location%\non-volatiles\files"
	%tools%mkdir.exe %location%\non-volatiles\files
	call :log_actions
)

REM echo ....................................................................................................
REM echo 					CALL DEBUG
REM echo ....................................................................................................
REM call :debug


:volatile_data
	echo. >> %actions%
	echo .................................................................................................... >> %actions%
	echo 					Acquisition of volatile data  >> %actions%
	echo .................................................................................................... >> %actions%
	echo. >> %actions%
	
	echo. >> %actions%
	echo Process information >> %actions%
	echo. >> %actions%
	echo Process list with "-t" arg for tree >> %actions%
	set _line="%tools%pslist.exe /accepteula -t > %location%\volatiles\processes\pstree.txt"
	%tools%pslist.exe /accepteula -t > %location%\volatiles\processes\pstree.txt
	call :log_actions
	echo Process list with linked services >> %actions%
	set _line="%tools%tasklist%arch%.exe /SVC /FO CSV > %location%\volatiles\processes\tasklist%arch%_services.csv"
	%tools%tasklist%arch%.exe /SVC /FO CSV > %location%\volatiles\processes\tasklist%arch%_services.csv
	call :log_actions
	echo Verbose mode tasklist%arch% >> %actions%
	set _line="%tools%tasklist%arch%.exe /V /FO CSV > %location%\volatiles\processes\tasklist%arch%_details.csv"
	%tools%tasklist%arch%.exe /V /FO CSV > %location%\volatiles\processes\tasklist%arch%_details.csv
	call :log_actions
	echo All handles with owner >> %actions%
	set _line="%tools%handle.exe -a /accepteula > %location%\volatiles\processes\handle.txt"
	%tools%handle.exe -a /accepteula > %location%\volatiles\processes\handle.txt
	call :log_actions
	echo All dlls used on the computer >> %actions%
	set _line="%tools%listdlls.exe /accepteula > %location%\volatiles\processes\dlls.txt"
	%tools%listdlls.exe /accepteula > %location%\volatiles\processes\dlls.txt
	call :log_actions
	echo Unsigned DLL >> %actions%
	set _line="%tools%listdlls.exe /accepteula -u > %location%\volatiles\processes\unsigned_dlls.txt"
	%tools%listdlls.exe /accepteula -u > %location%\volatiles\processes\unsigned_dlls.txt
	call :log_actions

	
	echo. >> %actions%
	echo Network information >> %actions%
	echo. >> %actions%
	echo tcp connections >> %actions%
	set _line="%tools%tcpvcon.exe -a -c /accepteula > %location%\volatiles\network\tcpview.csv"
	%tools%tcpvcon.exe -a -c /accepteula > %location%\volatiles\network\tcpview.csv
	call :log_actions

	
	echo. >> %actions%
	echo Session information >> %actions%
	echo loggedon sessions >> %actions%
	set _line="%tools%psloggedon.exe /accepteula > %location%\volatiles\misc\psloggedon.csv"
	%tools%psloggedon.exe /accepteula > %location%\volatiles\misc\psloggedon.csv
	call :log_actions
	
	echo. >> %actions%
	echo Remote open file >> %actions%
	set _line="%tools%psfile.exe /accepteula > %location%\volatiles\misc\psloggedon.csv"
	%tools%psfile.exe /accepteula > %location%\volatiles\misc\psloggedon.csv
	call :log_actions
	
	REM Dumping processes
	REM for /f "tokens=1,2 delims= " %%j in (%location%\volatiles\processes\pstree.txt) do (
		REM %tools%procdump.exe /accepteula -ma %%k %location%\volatiles\processes\dumps\%%j-%%k.dmp
	REM )

	
:non_volatile_data
	echo. >> %actions%
	echo .................................................................................................... >> %actions%
	echo					Acquisition of non volatile data  >> %actions%
	echo .................................................................................................... >> %actions%
	echo. >> %actions%
	

	%tools%wmic%arch% logicaldisk get DriveType,Name,VolumeName| %tools%grep 3 | %tools%cut -d: -f1 > %location%\non-volatiles\temp.txt
	for /f "tokens=2 delims= " %%i in (%location%\non-volatiles\temp.txt) do (
		echo Collecting data from drive %%i>>%actions%
		echo. >> %actions%
		echo MFT entries >> %actions%
		set _line="%tools%fls -r \\.\%%i: > %location%\non-volatiles\files\fls-%%i.txt"
		%tools%fls -r \\.\%%i: > %location%\non-volatiles\files\fls-%%i.txt
		call :log_actions
		
		echo Density of files >> %actions%
		%tools%densityscout -s cpl,exe,dll,ocx,sys,scr -l 0.1 -o %location%\non-volatiles\files\density-%%i.txt -r %%i:
		set _line="%tools%densityscout -s cpl,exe,dll,ocx,sys,scr -l 0.1 -o %location%\non-volatiles\files\density-%%i.txt -r %%i:"
		call :log_actions
		
		echo MD5sum of the file with high density.>>%actions%
		echo md5 *location > %location%\non-volatiles\files\density_md5-%%i.csv
		for /f "tokens=2 delims=|" %%j in (%location%\non-volatiles\files\density-%%i.txt) do (
			%tools%md5sum %%j >> %location%\non-volatiles\files\density_md5-%%i.csv
		)
	)

	set _line="del %location%\non-volatiles\temp.txt"
	del %location%\non-volatiles\temp.txt
	call :log_actions
	
	REM Really different between XP and 7. 
	
	echo Acquisition of events files >> %actions%
	echo Application events >> %actions%
	REM %arch% var is here only for legacy compliance between 32 and 64 bits.
	
	start %tools%rawcopy%arch% %event_path%%application% %location%\non-volatiles\events\
	set _line="start %tools%rawcopy%arch% %event_path%%application% %location%\non-volatiles\events\"
	call :log_actions
	
	echo Security events >> %actions%
	set _line="start %tools%rawcopy%arch% %event_path%%security% %location%\non-volatiles\events\"
	start %tools%rawcopy%arch% %event_path%%security% %location%\non-volatiles\events\
	call :log_actions
	
	echo System events >> %actions%
	set _line="start %tools%rawcopy%arch% %event_path%%system% %location%\non-volatiles\events\"
	start %tools%rawcopy%arch% %event_path%%system% %location%\non-volatiles\events\
	call :log_actions
	
	echo Acquisition of registry >> %actions%
	set _line="start %tools%rawcopy%arch% %WINDIR%\System32\config\SAM %location%\non-volatiles\registry"
	start %tools%rawcopy%arch% %WINDIR%\System32\config\SAM %location%\non-volatiles\registry
	call :log_actions
	
	set _line="start %tools%rawcopy%arch% %WINDIR%\System32\config\SECURITY %location%\non-volatiles\registry"
	start %tools%rawcopy%arch% %WINDIR%\System32\config\SECURITY %location%\non-volatiles\registry
	call :log_actions
	
	set _line="start %tools%rawcopy%arch% %WINDIR%\System32\config\SOFTWARE %location%\non-volatiles\registry"
	start %tools%rawcopy%arch% %WINDIR%\System32\config\SOFTWARE %location%\non-volatiles\registry
	call :log_actions
	
	set _line="start %tools%rawcopy%arch% %WINDIR%\System32\config\SYSTEM %location%\non-volatiles\registry"
	start %tools%rawcopy%arch% %WINDIR%\System32\config\SYSTEM %location%\non-volatiles\registry
	call :log_actions

	echo Acquisition of autorun >> %actions%
	set _line="%tools%autorunsc.exe -a -c -v /accepteula > %location%\non-volatiles\autorun.csv"
	%tools%autorunsc.exe -a -c -v /accepteula > %location%\non-volatiles\autorun.csv
	call :log_actions
	

	echo. >> %actions%
	echo .................................................................................................... >> %actions%
	echo 									END of Script   >> %actions%
	echo .................................................................................................... >> %actions%
	echo. >> %actions%
set _line=END
echo __________________________________________________________________________________________ >> %actions%

call :archiving


:log_actions
	REM Function to log what happened
	REM For each action, please log the command in the "_line" var et after the command launch, call :log_actions
	call :timestamp
	if %ERRORLEVEL% NEQ 0 (
		echo %timestamp% - ERRORLEVEL : %ERRORLEVEL% - %_line% >> %errors%
	) else (
		echo %timestamp% - %_line% >> %actions%
	)
	goto :EOF


:check_Permissions
	echo permissions check >> %actions%
    net session >nul 2>&1
    if %errorLevel% == 2 (
		echo %timestamp% - Failure: Current permissions inadequate. >> %errors%
		exit
    ) else (
		echo %timestamp% - Success: Administrative permissions confirmed. >> %actions%
		goto :EOF
    )
	
	
:timestamp
set m=%date:~4,1%
set d=%date:~0,2%
set y=%date:~6,4%
set hh=%time:~0,2%
set mm=%time:~3,2%
set ss=%time:~6,2%
set timestamp=%m%.%d%.%y%-%hh%.%mm%.%ss%
goto :EOF
	
:debug
echo ....................................................................................................
echo					DEBUGGING
echo ....................................................................................................

	REM Please, uncomment the call function and put your code here to test it.

exit

:archiving
echo "Archiving...">>%actions%
set _line="%tools%rar\Rar.exe a -dw -hpharvester4ir -id -r %_path%%archive%.cab %location%"
call :log_actions
%tools%rar\Rar.exe a -dw -hpharvester4ir -id -r %_path%%archive%.cab %location%
exit

