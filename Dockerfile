FROM python:3.12-slim-trixie

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

ENV DEBIAN_FRONTEND=noninteractive

# -----------------------------
# Ghidra configuration
# -----------------------------

ARG GHIDRA_VERSION=12.1.3
ARG GHIDRA_RELEASE_DATE=20260817
ARG GHIDRA_SHA256=93a5d11a9ad510622acaaf908c556a7b9b764d338e78a7567f3689bf5081fd54

ENV GHIDRA_HOME=/opt/ghidra
ENV GHIDRA_PROJECT_DIR=/workspace/ghidra_projects
ENV GHIDRA_SCRIPT_DIR=/opt/fwagent/ghidra_scripts

# -----------------------------
# System dependencies
# -----------------------------

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        binutils \
        bsdmainutils \
        ca-certificates \
        cpio \
        curl \
        file \
        findutils \
        git \
        gzip \
        grep \
        build-essential \
        openjdk-21-jdk-headless \
        p7zip-full \
        proot \
        python3-pip \
        qemu-user-static \
        squashfs-tools \
        tar \
        unzip \
        wget \
        xxd \
        xz-utils \
        \
        # unblob external extractors
        android-sdk-libsparse-utils \
        arj \
        cabextract \
        e2fsprogs \
        libmagic1 \
        unar \
        zlib1g-dev \
        liblzma-dev \
        liblzo2-dev \
        lzop \
        lziprecover \
        libhyperscan-dev \
        lz4 \
        mtd-utils \
        sleuthkit \
        zstd \
        binwalk \
    && rm -rf /var/lib/apt/lists/*

# -----------------------------
# Python firmware tools
# -----------------------------

RUN pip install --no-cache-dir \
        unblob

# -----------------------------
# Legacy firmware extractors
# -----------------------------

RUN set -eux; \
    tmpdir="$(mktemp -d)"; \
    git clone --depth 1 https://github.com/devttys0/sasquatch.git "${tmpdir}/sasquatch"; \
    cd "${tmpdir}/sasquatch"; \
    ./build.sh >/tmp/sasquatch-build.log 2>&1 || true; \
    cd squashfs4.3/squashfs-tools; \
    sed -i 's/ -Werror//g; s/-Werror//g' Makefile; \
    make clean >/dev/null 2>&1 || true; \
    make EXTRA_CFLAGS=-fcommon; \
    install -m 0755 sasquatch /usr/local/bin/sasquatch; \
    rm -rf "${tmpdir}" /tmp/sasquatch-build.log

# -----------------------------
# Install Ghidra
# -----------------------------

RUN mkdir -p /opt \
    && curl --fail --location --retry 5 --retry-delay 5 --retry-all-errors --connect-timeout 30 --speed-limit 1024 --speed-time 60 \
        "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_RELEASE_DATE}.zip" \
        -o /tmp/ghidra.zip \
    && echo "${GHIDRA_SHA256}  /tmp/ghidra.zip" | sha256sum -c - \
    && unzip /tmp/ghidra.zip -d /opt \
    && mv /opt/ghidra_${GHIDRA_VERSION}_PUBLIC ${GHIDRA_HOME} \
    && rm /tmp/ghidra.zip

RUN apt-get update \
    && apt-get install -y --no-install-recommends 7zip \
    && rm -rf /var/lib/apt/lists/* \
    && sevenzip_bin="$(command -v 7z || command -v 7zz || command -v 7za || command -v 7zr || find /usr -type f \( -name 7zz -o -name 7za -o -name 7zr \) -print -quit)" \
    && test -n "${sevenzip_bin}" \
    && if ! command -v 7z >/dev/null 2>&1; then \
        ln -s "${sevenzip_bin}" /usr/local/bin/7z; \
    fi

# -----------------------------
# Verify environment
# -----------------------------

RUN set -eux; \
    java -version; \
    file --version; \
    unsquashfs -version >/tmp/unsquashfs-version.txt 2>&1 || test -s /tmp/unsquashfs-version.txt; \
    cat /tmp/unsquashfs-version.txt; \
    command -v 7z; \
    7z i >/dev/null; \
    command -v unblob; \
    unblob --help >/tmp/unblob-help.txt; \
    command -v binwalk; \
    binwalk --help >/tmp/binwalk-help.txt; \
    command -v sasquatch; \
    sasquatch -version >/tmp/sasquatch-version.txt 2>&1 || test -s /tmp/sasquatch-version.txt; \
    cat /tmp/sasquatch-version.txt; \
    command -v readelf; \
    command -v objdump; \
    test -x "${GHIDRA_HOME}/support/analyzeHeadless"

# -----------------------------
# Application
# -----------------------------

WORKDIR /app

COPY . /app
RUN mkdir -p "${GHIDRA_SCRIPT_DIR}" \
    && cp -r /app/ghidra_scripts/. "${GHIDRA_SCRIPT_DIR}/"

RUN pip install --no-cache-dir .

RUN mkdir -p \
    /workspace \
    ${GHIDRA_PROJECT_DIR} \
    /work

WORKDIR /work

ENTRYPOINT ["fwagent"]
