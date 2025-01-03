FROM ubuntu:22.04

ENV LANG=C.UTF-8

ARG DEBIAN_FRONTEND=noninteractive
ARG BUILD_DATE="2025-01-02 16:35:28+08:00"
ARG KERNEL_VERSION="5.15.0-113-generic"
ARG LLVM_VERSION="17"

ENV RUSTUP_HOME=/usr/local/rustup \
	CARGO_HOME=/usr/local/cargo   \
	PATH=/usr/local/cargo/bin:$PATH

RUN apt-get update -y && \
    apt-get install -y --no-install-recommends \
      curl ca-certificates lsb-release wget software-properties-common gnupg clang-format \
      build-essential make libelf1 libelf-dev zlib1g-dev pkg-config "linux-headers-$(KERNEL_VERSION)" && \
	update-ca-certificates	&& \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install LLVM (clang) and make it available in $PATH
RUN curl -O https://apt.llvm.org/llvm.sh && chmod +x llvm.sh && ./llvm.sh $LLVM_VERSION && rm -rf llvm.sh
ENV PATH=/usr/lib/llvm-${LLVM_VERSION}/bin/:$PATH

# Install Rust
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y \
	&& rustup --version                          \
	&& cargo --version                           \
	&& rustc --version

LABEL \
    org.opencontainers.image.name="jheapusage-dev" \
    org.opencontainers.image.description="Development Container for jheapusage" \
    org.opencontainers.image.url="https://github.com/REASY/jheapusage" \
    org.opencontainers.image.source="https://github.com/REASY/jheapusage.git" \
    org.opencontainers.image.version="1.0" \
    org.opencontainers.image.created="$BUILD_DATE" \
    org.opencontainers.image.licenses="MIT License" \
    org.opencontainers.image.authors="Artavazd Balaian <reasyu@gmail.com>" \
    org.opencontainers.image.base.name="ubuntu:22.04"

ENTRYPOINT ["/bin/bash"]

# groupadd -g 12345 test-group && useradd test-user --system --create-home --no-log-init -u 12345 -g 12345