#!/bin/bash
OS=$1
TARGET=$2
set -e
set -x

export PATH="$HOME/.cargo/bin:$PATH"

currentDir="$(pwd)"
parentDir="$(dirname "$currentDir")"

echo "Download, unzip and rename pyapp folder"

curl -L https://github.com/ofek/pyapp/releases/latest/download/source.tar.gz -o pyapp-source.tar.gz

rm -rf pyapp_$OS
mkdir -p pyapp_$OS
tar -xzf pyapp-source.tar.gz --strip-components=1 -C pyapp_$OS

echo "Delete pyapp-source.tar.gz"
rm -f pyapp-source.tar.gz

if [ "$OS" = "linux" ]; then
    source "$HOME/miniconda3/etc/profile.d/conda.sh"
fi

eval "$(conda shell.bash hook)"
envName="ffl_python_temp"
rm -rf $envName

echo "Activating conda environment: $envName"
conda create -n "$envName" python=3.12 -y

conda activate "$envName"

export PYTHONIOENCODING=utf-8

if [ "$OS" = "linux" ]; then
    cp REQUIREMENTS.txt REQUIREMENTS.txt.bak
    grep -vi -e "Gooey==1.0.8.1" -e "pyinstaller" REQUIREMENTS.txt > REQUIREMENTS.txt.tmp 
    mv REQUIREMENTS.txt.tmp REQUIREMENTS.txt
fi

python3 -m pip install -r REQUIREMENTS.txt 
# Used only for DistUtil.py not bundled in final executable.
python3 -m pip install pefile conda-pack setuptools wheel pip

if [ "$OS" = "linux" ]; then
    mv REQUIREMENTS.txt.bak REQUIREMENTS.txt
fi

currentDir="$(pwd)"
parentDir="$(dirname "$currentDir")"

echo "Copy server static folders (js, client, css, locales) to FileShare/static"
serverStaticDir="$parentDir/FileShareServer/static"
targetStaticDir="$currentDir/static"

if [ -d "$serverStaticDir" ]; then
    for folder in js client css locales; do
        if [ -d "$serverStaticDir/$folder" ]; then
            echo "Copying server static folder: $folder"
            rm -rf "$targetStaticDir/$folder"
            cp -r "$serverStaticDir/$folder" "$targetStaticDir/"
        else
            echo "Warning: Server static folder not found: $serverStaticDir/$folder"
        fi
    done
else
    echo "Warning: Server static directory not found: $serverStaticDir"
fi

echo "Copy Setup.py"
cp "$currentDir/dist/CLI/Setup.py" "$parentDir/"

cd "$parentDir"

echo "Build wheel"
python3 Setup.py bdist_wheel

cd dist

echo "Get wheel filename"

wheelFile=""
for f in ffl*.whl; do
    wheelFile="$f"
    break
done

if [ -z "$wheelFile" ]; then
    echo "No wheel file found!"
    exit 1
fi

echo "$wheelFile"

echo "Installing wheel: $wheelFile"
python3 -m pip install "$wheelFile" --force-reinstall --no-warn-script-location


cd ../FileShare

echo "Copy wheel file to pyapp folder"
cp "../dist/$wheelFile" "$currentDir/pyapp_$OS/"

cd ..

echo "Delete unused files"
rm -rf dist
rm -rf build
rm -rf ffl.egg-info
rm -f Setup.py

cd FileShare

rm -f ffl_python_temp.tar.gz
conda pack -n ffl_python_temp -o ffl_python_temp.tar.gz

mkdir -p ffl_python_temp
tar -xzf ffl_python_temp.tar.gz -C ffl_python_temp

echo "Clean python environment"
python DistUtils.py pyapp clean --target-dir ffl_python_temp

cd ffl_python_temp

if [ "$OS" = "darwin" ]; then
    python3 -m compileall --invalidation-mode=unchecked-hash -b -q lib  || true
elif [ "$TARGET" = "manyLinux" ]; then
	cd ..
	cp "$currentDir/dist/CLI/linux/RemoveSym.py" "$currentDir/"
	python RemoveSym.py ffl_python_temp
	cd ffl_python_temp
    python3 -m compileall --invalidation-mode=unchecked-hash -b -q lib
else
	python3 -m compileall --invalidation-mode=unchecked-hash -b -q lib
fi

find . -type f -name "*.py" -exec rm -f {} +
mv bin/python3.12 bin/ffl


tar -czf ../ffl_python.tar.gz . 

cd ..
cp "ffl_python.tar.gz" "$currentDir/pyapp_$OS/"

cd pyapp_$OS

export PYAPP_PROJECT_PATH="./$wheelFile"
export PYAPP_SKIP_INSTALL='1'
export PYAPP_DISTRIBUTION_SITE_PACKAGES_PATH='./lib/python3.12/site-packages'
export PYAPP_DISTRIBUTION_PYTHON_PATH='./bin/ffl'
export PYAPP_DISTRIBUTION_EMBED='1'
export PYAPP_FULL_ISOLATION='1'
export PYAPP_PROJECT_NAME='ffl'
export PYAPP_DISTRIBUTION_PATH='./ffl_python.tar.gz'
export PYAPP_EXEC_SPEC='FileShare.Core:main'
export PYAPP_PASS_LOCATION='1'

cargo clean

if [ "$OS" = "darwin" ]; then
    # # Build for Intel (x86_64)
    rustup target add x86_64-apple-darwin
    cargo build --target=x86_64-apple-darwin --release
    cp "target/x86_64-apple-darwin/release/pyapp" \
       "../dist/CLI/$OS/ffl_x86_64"
    chmod +x ../dist/CLI/$OS/ffl_x86_64

    # Build for Apple Silicon (arm64)
    rustup target add aarch64-apple-darwin
    cargo build --target=aarch64-apple-darwin --release
    cp "target/aarch64-apple-darwin/release/pyapp" \
       "../dist/CLI/$OS/ffl_aarch64"
    chmod +x ../dist/CLI/$OS/ffl_aarch64

    # # Merge into a universal binary
    # lipo -create -output target/ffl_universal \
    #     target/x86_64-apple-darwin/release/pyapp \
    #     target/aarch64-apple-darwin/release/pyapp

    # mkdir -p "dist/CLI/$OS"
    # cp target/ffl_universal "dist/CLI/$OS/ffl_universal"
    # chmod +x "dist/CLI/$OS/ffl_universal"

    cd ..

else

    rustup target add x86_64-unknown-linux-musl

    cargo build --target=x86_64-unknown-linux-musl --release

    cd ..

    cp "pyapp_$OS/target/x86_64-unknown-linux-musl/release/pyapp" "dist/CLI/$OS/ffl"

fi



rm -rf ffl_python_temp
rm -rf pyapp_$OS
rm -f ffl_python_temp.tar.gz
rm -f ffl_python.tar.gz

conda deactivate
conda remove -n ffl_python_temp --all -y

echo "✅ Build complete: dist/CLI/$OS/ffl"
