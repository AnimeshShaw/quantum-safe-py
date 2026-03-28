FROM python:3.12-slim

# Install build tools needed by oqs-python (which compiles a small C extension)
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc \
        libssl-dev \
        && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy dependency declarations first so Docker can cache the install layer
COPY pyproject.toml ./
COPY src/ src/

# Install the library with the liboqs extra (pulls in oqs-python + liboqs binary)
RUN pip install --no-cache-dir -e ".[liboqs]"

# Copy benchmark harnesses and results directory
COPY tests/bench/ tests/bench/
COPY results/ results/

# Default: run the full benchmark suite (KEM + signatures) with liboqs
CMD ["sh", "-c", \
     "python -X utf8 tests/bench/bench_kem.py --with-pqc && \
      python -X utf8 tests/bench/bench_signatures.py --with-pqc"]
