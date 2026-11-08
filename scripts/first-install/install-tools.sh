#!/usr/bin/env bash
set -euo pipefail

[[ $(uname -s) == Darwin ]] || { echo 'The first-install image preparation requires macOS.' >&2; exit 1; }
brew install dtc llvm lld cmake mtools ninja glslang shaderc spirv-tools bison pkgconf rustup unifdef blacktop/tap/ipsw

# This PATH setup follows the pinned device packaging workflow.
for entry in "$HOME/.cargo/bin" "$(brew --prefix llvm)/bin" "$(brew --prefix lld)/bin" "$(brew --prefix bison)/bin"; do
  printf '%s\n' "$entry" >> "$GITHUB_PATH"
done
export PATH="$HOME/.cargo/bin:$(brew --prefix bison)/bin:$PATH"
rustup toolchain install 1.98.0 --profile minimal --component rust-src

ok=1
for command in clang xcodebuild xcrun make git ninja cmake dtc fdtget fdtput aea compression_tool hdiutil diskutil mformat mcopy ipsw unifdef; do
  command -v "$command" >/dev/null || { echo "missing tool: $command" >&2; ok=0; }
done
for command in lld-link llvm-lib llvm-rc llvm-nm llvm-objcopy; do
  [[ -x $(brew --prefix llvm)/bin/$command || -x $(brew --prefix lld)/bin/$command ]] || { echo "missing tool: $command" >&2; ok=0; }
done
[[ $ok == 1 ]]
python3 -c 'import sys; assert sys.version_info >= (3, 11), "Python 3.11 or newer is required"'
xcodebuild -version
xcrun --sdk iphoneos --show-sdk-version
df -h "$GITHUB_WORKSPACE"
