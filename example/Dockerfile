FROM ubuntu:24.04

# 1.21.3
ARG GO_VERSION=1.22.5

# update sources
RUN apt update

# install common tools
RUN apt install -y curl \
    git \
    wget \
    jq \
    unzip \
    vim

# install golang
RUN mkdir -p /go/bin /go/src && \
    curl --fail --location "https://go.dev/dl/go$GO_VERSION.linux-amd64.tar.gz" \
    | tar -xz -C /usr/local
ENV GOPATH="/go"
ENV PATH="$GOPATH/bin:/usr/local/go/bin:$PATH"

# install libprotobuf-mutator deps
RUN apt install -y protobuf-compiler libprotobuf-dev binutils cmake \
    ninja-build liblzma-dev libz-dev pkg-config autoconf libtool \
    clang python3-dev

# install libprotobuf-mutator
# NOTE: only works with v1.1 tag
RUN git clone https://github.com/google/libprotobuf-mutator.git && \
    cd libprotobuf-mutator && \
    git checkout v1.1 && \
    mkdir build && cd build && \
    cmake .. -GNinja -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_BUILD_TYPE=Debug && \
    ninja check && \
    ninja install

    