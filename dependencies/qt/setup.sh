#!/bin/bash

ROOT=$(pwd)

if [[ ! $(which git) ]]; then
    echo "git is not installed"
    exit -1
fi

git clone -b 5.15 https://github.com/qt/qtbase.git ${ROOT}/qtbase
git clone -b 5.15 https://github.com/qt/qttools.git ${ROOT}/qttools
git clone -b 5.15 https://github.com/qt/qttranslations.git ${ROOT}/qttranslations
git clone -b 5.15 https://github.com/qt/qtdeclarative.git ${ROOT}/qtdeclarative

cd ${ROOT}/qtbase
patch -s -p1 < ${ROOT}/42/dependencies/qt/stack_protector.patch
cd ${ROOT}/qtdeclarative
patch -s -p1 < ${ROOT}/42/dependencies/qt/scenegraph.patch
cd ${ROOT}
