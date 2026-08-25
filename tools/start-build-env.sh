#!/bin/bash
docker pull ivano/asuswrt-merlin-toolchains-custom:latest
docker run -it --rm -v "$PWD:/build"  -u $(id -u ${USER}):$(id -g ${USER}) \
       ivano/asuswrt-merlin-toolchains-custom:latest /bin/bash
