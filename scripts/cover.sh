#!/usr/bin/env bash
set -e
cargo llvm-cov --ignore-filename-regex '(^|/)src/test_support/' --lcov --output-path target/lcov.info
cargo llvm-cov --ignore-filename-regex '(^|/)src/test_support/'