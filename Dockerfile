FROM python:3.12-slim

# ── Stage 1: build liboqs ──────────────────────────────────────────────────
# oqs-python's auto-installer has a known bug: it tries to clone branch
# matching its own version number (e.g. "0.14.1") instead of the correct
# liboqs tag ("0.15.0"). We bypass it entirely by building liboqs from
# source and installing it as a system library before pip install.

RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc cmake make git libssl-dev libc6-dev \
        && rm -rf /var/lib/apt/lists/*

# Build liboqs 0.15.0 as a shared library and install to /usr/local
# -DOQS_DIST_BUILD=ON  → portable binary (no CPU-feature detection at runtime)
# -DBUILD_SHARED_LIBS=ON → produces liboqs.so.0.15.0 + symlinks
ARG LIBOQS_TAG=0.15.0
RUN git clone --depth 1 --branch ${LIBOQS_TAG} \
        https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs && \
    cmake -S /tmp/liboqs -B /tmp/liboqs/build \
          -DOQS_DIST_BUILD=ON \
          -DBUILD_SHARED_LIBS=ON \
          -DCMAKE_BUILD_TYPE=Release \
          -DCMAKE_INSTALL_PREFIX=/usr/local && \
    cmake --build /tmp/liboqs/build --parallel "$(nproc)" && \
    cmake --install /tmp/liboqs/build && \
    ldconfig && \
    rm -rf /tmp/liboqs

# ── Stage 2: install the quantum-safe package ─────────────────────────────

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src/ src/

# oqs-python will now find liboqs.so at /usr/local/lib and skip the auto-installer
RUN pip install --no-cache-dir ".[liboqs]"

# Sanity-check: confirm liboqs loads and ML-KEM-768 round-trips correctly
RUN python -c "import warnings; warnings.filterwarnings('ignore'); import oqs; kem = oqs.KeyEncapsulation('ML-KEM-768'); pub = kem.generate_keypair(); ct, ss = kem.encap_secret(pub); ss2 = kem.decap_secret(ct); assert ss == ss2; print('liboqs OK:', oqs.oqs_version(), '— ML-KEM-768 round-trip: OK')"

# ── Stage 3: benchmark harnesses ─────────────────────────────────────────

COPY tests/bench/ tests/bench/
COPY results/ results/

# Expose a volume for persisting JSON snapshots to the host
VOLUME ["/app/results"]

# Default command: full suite (KEM + signatures) with real PQC
CMD ["sh", "-c", \
     "python -X utf8 tests/bench/bench_kem.py --with-pqc && \
      python -X utf8 tests/bench/bench_signatures.py --with-pqc"]
