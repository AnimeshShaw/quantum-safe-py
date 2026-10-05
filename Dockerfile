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

# hatch_build.py is required, not optional: pyproject.toml registers a custom
# build hook that lives in it, so without this line pip fails during "getting
# requirements to build wheel" and the image cannot be built at all. That broke
# when the liboqs vendoring hook was introduced, and with it the claim that every
# published number is reproducible from a single Docker command.
# THIRD_PARTY_LICENSES.md and licenses/ are listed in pyproject.toml's wheel force-include, so the build fails without them.
COPY pyproject.toml README.md hatch_build.py THIRD_PARTY_LICENSES.md ./
COPY licenses/ licenses/
COPY src/ src/

# oqs-python will now find liboqs.so at /usr/local/lib and skip the auto-installer.
# QUANTUM_SAFE_VENDOR_LIBOQS is deliberately left unset: the vendoring hook is for
# released wheels, and this image wants the system liboqs built above so that the
# measured binary is the one whose build flags are documented for ENV-2.
RUN pip install --no-cache-dir ".[liboqs]"

# Sanity-check: confirm liboqs loads and ML-KEM-768 round-trips correctly
RUN python -c "import warnings; warnings.filterwarnings('ignore'); import oqs; kem = oqs.KeyEncapsulation('ML-KEM-768'); pub = kem.generate_keypair(); ct, ss = kem.encap_secret(pub); ss2 = kem.decap_secret(ct); assert ss == ss2; print('liboqs OK:', oqs.oqs_version(), '— ML-KEM-768 round-trip: OK')"

# ── Stage 3: benchmark harnesses ─────────────────────────────────────────

COPY tests/bench/ tests/bench/
COPY tests/conformance/ tests/conformance/
COPY results/ results/

# The commit this image was built from, recorded in every benchmark file (there is no .git inside the image)
ARG QS_GIT_COMMIT=unknown
ENV QS_GIT_COMMIT=${QS_GIT_COMMIT}

# Expose a volume for persisting JSON snapshots to the host
VOLUME ["/app/results"]

# Default command: full suite (KEM + signatures) with real PQC
CMD ["sh", "-c", \
     "python -X utf8 tests/bench/bench_kem.py --with-pqc && \
      python -X utf8 tests/bench/bench_signatures.py --with-pqc"]
