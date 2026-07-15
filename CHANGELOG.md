# Changelog

## [1.0.0](https://github.com/jdx/jdx-tar/compare/v0.0.1...v1.0.0) - 2026-07-15

### Other

- split format and unpack modules ([#9](https://github.com/jdx/jdx-tar/pull/9))
- cover unpack callbacks and summary ([#8](https://github.com/jdx/jdx-tar/pull/8))
- correct windows sparse behavior and tighten readme prose ([#7](https://github.com/jdx/jdx-tar/pull/7))
- welcome tar writing contributions ([#6](https://github.com/jdx/jdx-tar/pull/6))

## [0.0.1](https://github.com/jdx/jdx-tar/compare/v0.0.0...v0.0.1) - 2026-07-15

### Fixed

- account for unix-only permission metadata
- avoid cross-toolchain unused binding warning

### Other

- add sparse archive compatibility corpus
- expand readme with rationale, comparison table, and usage guidance ([#4](https://github.com/jdx/jdx-tar/pull/4))
- Configure Renovate ([#1](https://github.com/jdx/jdx-tar/pull/1))
- *(release)* add trusted release-plz workflow

## 0.0.0 - 2026-07-15

- Initial placeholder release establishing the crate for trusted publishing.
- Streaming ustar, GNU, and PAX reader.
- GNU sparse 0.0, 0.1, 1.0, and old GNU sparse extraction.
- Secure extraction options, progress hooks, and extraction summaries.
