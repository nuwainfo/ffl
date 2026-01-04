#!/bin/bash
OS=$1
TARGET=$2
set -e
set -x

set -o pipefail

currentStep="INIT"

step() {
    currentStep="$1"
    echo
    echo "=============================="
    echo "▶ STEP: $currentStep"
    echo "=============================="
}

currentDir="$(pwd)"
parentDir="$(dirname "$currentDir")"
export PATH="$HOME/.cargo/bin:$PATH"

downloadPyapp() {

    currentDir="$(pwd)"
    parentDir="$(dirname "$currentDir")"

    echo "Download, unzip and rename pyapp folder"

    curl -L https://github.com/ofek/pyapp/releases/latest/download/source.tar.gz -o pyapp-source.tar.gz

    rm -rf pyapp_$OS
    mkdir -p pyapp_$OS
    tar -xzf pyapp-source.tar.gz --strip-components=1 -C pyapp_$OS

    echo "Delete pyapp-source.tar.gz"
    rm -f pyapp-source.tar.gz

}

createWheel() {
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

    echo "Installing wheel: $wheelFile"
    python3 -m pip install "$wheelFile" --force-reinstall --no-warn-script-location

    cd ../FileShare

    echo "Copy wheel file to pyapp folder"
    cp "../dist/$wheelFile" "$currentDir/pyapp_$OS/"
    export wheelFile
    
    cd ..

    echo "Delete unused files"
    rm -rf dist
    rm -rf build
    rm -rf ffl.egg-info
    rm -f Setup.py

    cd FileShare
}

createPythonTarGz() {
    local platform="${1:-native}"

    unset CONDA_SUBDIR
    envName="ffl_python_temp"

    if [ "$OS" = "darwin" ] && [ "$platform" = "x86_64" ]; then
        export CONDA_SUBDIR=osx-64
        envName="ffl_python_temp_x86_64"
    fi

    if [ "$OS" = "linux" ]; then
        source "$HOME/miniconda3/etc/profile.d/conda.sh"
    fi

    eval "$(conda shell.bash hook)"
    rm -rf "$envName"

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

    createWheel

    rm -f "$envName.tar.gz"
    conda pack -n "$envName" -o "$envName.tar.gz"

    mkdir -p "$envName"
    tar -xzf "$envName.tar.gz" -C "$envName"

    echo "Clean python environment"
    python DistUtils.py pyapp clean --target-dir "$envName"

    cd $envName

    if [ "$OS" = "darwin" ]; then
        python3 -m compileall --invalidation-mode=unchecked-hash -b -q lib  || true
    elif [ "$TARGET" = "manyLinux" ]; then
        cd ..
        cp "$currentDir/dist/CLI/linux/RemoveSym.py" "$currentDir/"
        python RemoveSym.py "$envName"
        cd "$envName"
        python3 -m compileall --invalidation-mode=unchecked-hash -b -q lib
    else
        python3 -m compileall --invalidation-mode=unchecked-hash -b -q lib
    fi

    find . -type f -name "*.py" -exec rm -f {} +
    mv bin/python3.12 bin/ffl

    if [ "$OS" = "darwin" ] && [ "$platform" = "x86_64" ]; then
        tarGzName="ffl_python_x86_64.tar.gz"
    else
        tarGzName="ffl_python.tar.gz"
    fi

    tar -czf "../$tarGzName" . 

    cd ..
    cp "$tarGzName" "$currentDir/pyapp_$OS/"

    unset CONDA_SUBDIR
}

copyServerStatic() {

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

}

createApp() {
    local platform="${1:-native}"
    cd pyapp_$OS

    cargo clean
    echo "$wheelFile"

    export PYAPP_PROJECT_PATH="./$wheelFile"
    export PYAPP_SKIP_INSTALL='1'
    export PYAPP_DISTRIBUTION_SITE_PACKAGES_PATH='./lib/python3.12/site-packages'
    export PYAPP_DISTRIBUTION_PATH='./ffl_python.tar.gz'
    export PYAPP_DISTRIBUTION_PYTHON_PATH='./bin/ffl'
    export PYAPP_DISTRIBUTION_EMBED='1'
    export PYAPP_FULL_ISOLATION='1'
    export PYAPP_PROJECT_NAME='ffl'
    export PYAPP_EXEC_SPEC='FileShare.Core:main'
    export PYAPP_PASS_LOCATION='1'

    if [ "$OS" = "darwin" ] && [ "$platform" = "x86_64" ]; then
        export PYAPP_DISTRIBUTION_PATH='./ffl_python_x86_64.tar.gz'
        rustup target add x86_64-apple-darwin
        cargo build --target=x86_64-apple-darwin --release
        cp "target/x86_64-apple-darwin/release/pyapp" \
        "../dist/CLI/$OS/ffl_x86_64"
        chmod +x ../dist/CLI/$OS/ffl_x86_64
    else
        export PYAPP_DISTRIBUTION_PATH='./ffl_python.tar.gz'
        if [ "$OS" = "darwin" ]; then
            rustup target add aarch64-apple-darwin
            cargo build --target=aarch64-apple-darwin --release
            cp "target/aarch64-apple-darwin/release/pyapp" \
            "../dist/CLI/$OS/ffl_aarch64"
            chmod +x ../dist/CLI/$OS/ffl_aarch64
        else
            rustup target add x86_64-unknown-linux-musl
            cargo build --target=x86_64-unknown-linux-musl --release
            cp "target/x86_64-unknown-linux-musl/release/pyapp" "../dist/CLI/$OS/ffl"
        fi
    fi

    cd ..
}

cleanEnvironment() {
    rm -rf ffl_python_temp
    rm -rf pyapp_$OS
    rm -f ffl_python_temp.tar.gz
    rm -f ffl_python_temp_x86_64.tar.gz
    rm -f ffl_python.tar.gz
    rm -f ffl_python_x86_64.tar.gz

    conda deactivate
    conda remove -n ffl_python_temp --all -y

    echo "✅ Build complete: dist/CLI/$OS/ffl"
}


step "START build OS=$OS TARGET=${TARGET:-none}"

step "Download pyapp"
downloadPyapp

if [ "$OS" = "darwin" ]; then

    step "Copy server static"
    copyServerStatic

    step "Create Python env (darwin native)"
    createPythonTarGz "aarch"

    step "Create Python env (darwin x86_64)"
    createPythonTarGz "x86_64"

    step "Build app (darwin aarch64)"
    createApp "aarch"

    step "Build app (darwin x86_64)"
    createApp "x86_64"

    step "Cleanup"
    cleanEnvironment

elif [ "$OS" = "linux" ]; then

    step "Copy server static"
    copyServerStatic

    step "Create Conda env (linux${TARGET:+ / $TARGET})"
    createPythonTarGz "x86_64"

    step "Build app (linux)"
    createApp "x86_64"

    step "Cleanup"
    cleanEnvironment

else
    echo "❌ Unknown OS: $OS"
    echo "Usage:"
    echo "  BuildCLI.sh darwin"
    echo "  BuildCLI.sh linux"
    echo "  BuildCLI.sh linux manyLinux"
    exit 1
fi





