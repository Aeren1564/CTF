FROM node:23.9.0-slim AS base

RUN apt-get update && apt-get upgrade -y && apt-get install -y \
    curl \
    g++ \
    git \
    pkg-config \
    python3

FROM base AS build

RUN git clone https://chromium.googlesource.com/chromium/tools/depot_tools.git
ENV PATH="/depot_tools:${PATH}"
RUN fetch v8

WORKDIR /v8

RUN git checkout 13.6.1
RUN gn gen out/build --args='is_debug=false v8_use_external_startup_data=false target_cpu="x64" use_goma=false v8_enable_i18n_support=false symbol_level=0'
RUN ninja -C out/build d8

FROM base AS chall

WORKDIR /chall
COPY --from=build /v8/out/build/d8 .
COPY secret.txt gen.js chall.py .

ENTRYPOINT ["python3", "chall.py"]
