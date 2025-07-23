#!/usr/bin/env sh

set -xe

if [[ ! -d "mpc-lib" ]]; then
     git clone https://github.com/fireblocks/mpc-lib
     pushd mpc-lib
     git checkout a8f6a6f0062532f9c86ad39805a68481ba3d106c
     git apply ../challenge.diff
     git diff
     popd
fi

docker build -t mpc-lib -f Dockerfile.build .
docker run -v$(pwd):/usr/src/mpc-lib/ -it mpc-lib make
cp ./build/mpc-lib/src/common/libcosigner.so lib/
cp ./build/challenge .
patchelf --set-rpath ./lib challenge
