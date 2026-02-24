@echo off

call conda activate %1
set PYTHONIOENCODING=utf-8

set currentDir=%CD%
set parentDir=%CD%\..

echo "Download, unzip and rename pyapp folder"

powershell -Command ^
"Invoke-WebRequest https://github.com/ofek/pyapp/releases/latest/download/source.zip -OutFile pyapp-source.zip; ^
7z x pyapp-source.zip; ^
mv pyapp-v* pyapp;"

echo "Delete pyapp.zip"
del pyapp-source.zip

echo "Copy server static folders (js, client, css, locales) to FileShare\static"
set serverStaticDir=%parentDir%\FileShareServer\static
set targetStaticDir=%currentDir%\static

if exist "%serverStaticDir%" (
    for %%f in (js client css locales) do (
        if exist "%serverStaticDir%\%%f" (
            echo Copying server static folder: %%f
            xcopy "%serverStaticDir%\%%f" "%targetStaticDir%\%%f\" /E /I /Y >nul
        ) else (
            echo Warning: Server static folder not found: %serverStaticDir%\%%f
        )
    )
) else (
    echo Warning: Server static directory not found: %serverStaticDir%
)

echo "Copy Setup.py"
copy "%currentDir%\dist\CLI\Setup.py" "%parentDir%" /Y

cd ..

echo "Build wheel"
python -m pip install --upgrade --force-reinstall wheel setuptools
python Setup.py bdist_wheel

cd dist

echo "Get wheel filename"
set "wheelFile="
for %%f in (ffl*.whl) do (
    set "wheelFile=%%f"
    goto :doneGet
)
:doneGet

echo "%wheelFile%"

echo "Installing wheel: %wheelFile%"
python -m pip install "%wheelFile%" --force-reinstall --no-warn-script-location

cd ..
cd FileShare

echo "Copy wheel file to pyapp folder"
copy "..\dist\%wheelFile%" "%currentDir%\pyapp" /Y

cd ..

echo "Delete unused files"
rd /s /q dist
rd /s /q build
rd /s /q ffl.egg-info
del Setup.py

cd FileShare

echo "Clean python environment"
python DistUtils.py pyapp clean

set copyEnv=%1_copy

cd %copyEnv%

echo "%copyEnv%"

call conda deactivate

powershell -Command ".\python.exe -m compileall --invalidation-mode=unchecked-hash -b -q Lib"
powershell -Command "Get-ChildItem -Path 'Lib' -Recurse -Filter *.py | Remove-Item -Force"
powershell -Command "Rename-Item 'python.exe' 'ffl.exe'"
powershell -Command ^
"Invoke-WebRequest https://github.com/electron/rcedit/releases/download/v2.0.0/rcedit-x64.exe -OutFile rcedit.exe; ^
.\rcedit.exe 'ffl.exe' --set-version-string 'FileDescription' 'FastFileLink CLI'"

del rcedit.exe

cd ..

call conda activate %1

echo "Compress python environment"
python DistUtils.py pyapp compress %copyEnv%


echo "Copy python.zip to pyapp"
copy "%currentDir%\ffl_python.zip" "%currentDir%\pyapp" /Y

echo "Delete unused zip"
del ffl_python.zip

cd pyapp

echo "Wrap exe"

powershell -Command ^
"$env:PYAPP_EXEC_SPEC = 'FileShare.Core:main'; ^
$env:PYAPP_DISTRIBUTION_PATH = '.\ffl_python.zip'; ^
$env:PYAPP_PROJECT_NAME = 'ffl'; ^
$env:PYAPP_FULL_ISOLATION = '1'; ^
$env:PYAPP_DISTRIBUTION_EMBED = '1'; ^
$env:PYAPP_DISTRIBUTION_PYTHON_PATH = '.\ffl.exe'; ^
$env:PYAPP_DISTRIBUTION_SITE_PACKAGES_PATH = 'Lib\site-packages'; ^
$env:PYAPP_SKIP_INSTALL = '1'; ^
$env:PYAPP_PROJECT_PATH = '.\%wheelFile%'; ^
$env:PYAPP_PASS_LOCATION = '1'; ^
cargo clean;cargo build --release;"

cd ..

echo "Wait for pyapp.exe to be released..."
:waitExe
if exist "%currentDir%\pyapp\target\release\pyapp.exe" (
    copy "%currentDir%\pyapp\target\release\pyapp.exe" "%currentDir%\dist\CLI\windows\ffl_tmp.exe" /Y 2>nul
    if errorlevel 1 (
        timeout /t 1 >nul
        goto waitExe
    )
) else (
    echo "pyapp.exe not found, abort"
    exit /b 1
)

if exist "%currentDir%\dist\CLI\windows\ffl.exe" del /f /q "%currentDir%\dist\CLI\windows\ffl.exe"
ren "%currentDir%\dist\CLI\windows\ffl_tmp.exe" "ffl.exe"

echo "Delete pyapp folder"
rd /s /q "%currentDir%\pyapp"
