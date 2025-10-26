#!/usr/bin/env bash
# Build and push douteki-dns Docker images to GitHub Container Registry

set -euo pipefail
set -a
source .env
set +a

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'
GITHUB_REPOSITORY=Julgodis/douteki-dns

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "${ROOT_DIR}"

REGISTRY="ghcr.io"
IMAGE_NAME="douteki-dns"
PUSH=0

if [[ $# -gt 0 ]]; then
  if [[ "$1" == "--push" ]]; then
    PUSH=1
  else
    echo -e "${RED}Unknown argument: $1${NC}" >&2
    echo "Usage: scripts/build-image.sh [--push]" >&2
    exit 1
  fi
fi

if ! command -v docker >/dev/null 2>&1; then
  echo -e "${RED}Error: docker is not installed${NC}" >&2
  exit 1
fi

VERSION=$(grep '^version' Cargo.toml | head -1 | cut -d'"' -f2)
if [[ -z "${VERSION}" ]]; then
  echo -e "${RED}Error: Could not determine version from Cargo.toml${NC}" >&2
  exit 1
fi

echo -e "${GREEN}Building douteki-dns version ${VERSION}${NC}"

GIT_USER=${GITHUB_USERNAME:-}
if [[ -z "${GIT_USER}" ]]; then
  GIT_USER=$(git config user.name 2>/dev/null | tr '[:upper:]' '[:lower:]' | tr -d ' ')
fi

if [[ -z "${GIT_USER}" ]]; then
  echo -e "${RED}Error: Could not determine GitHub username${NC}" >&2
  echo "Set GITHUB_USERNAME environment variable or configure git user.name" >&2
  exit 1
fi

FULL_IMAGE="${REGISTRY}/${GIT_USER}/${IMAGE_NAME}"

echo -e "${YELLOW}Image will be tagged as:${NC}"
echo "  - ${FULL_IMAGE}:${VERSION}"
echo "  - ${FULL_IMAGE}:latest"
echo

echo -e "${GREEN}Running cargo fmt --check and cargo test --release${NC}"
cargo fmt --all -- --check
cargo test --all --release

echo -e "${GREEN}Building Docker image (with cache)${NC}"
docker build \
  --pull \
  -t "${FULL_IMAGE}:${VERSION}" \
  -t "${FULL_IMAGE}:latest" \
  .

echo -e "${GREEN}Build successful!${NC}"
echo

if [[ ${PUSH} -ne 1 ]]; then
  echo -e "${YELLOW}Image built locally. To push to GitHub Container Registry:${NC}"
  echo "  1. Login: echo \$GITHUB_TOKEN | docker login ${REGISTRY} -u ${GIT_USER} --password-stdin"
  echo "  2. Push: scripts/build-image.sh --push"
  echo
  echo -e "${YELLOW}Or rerun with --push if already logged in${NC}"
  exit 0
fi

if ! docker info 2>/dev/null | grep -q "${REGISTRY}"; then
  echo -e "${YELLOW}Not logged in to ${REGISTRY}${NC}"
  if [[ -z "${GITHUB_TOKEN:-}" ]]; then
    echo -e "${RED}Error: GITHUB_TOKEN environment variable not set${NC}" >&2
    echo "Create a token at https://github.com/settings/tokens with write:packages" >&2
    exit 1
  fi
  echo -e "${GREEN}Logging in to ${REGISTRY} as ${GIT_USER}${NC}"
  echo "${GITHUB_TOKEN}" | docker login "${REGISTRY}" -u "${GIT_USER}" --password-stdin
fi

echo -e "${GREEN}Pushing ${FULL_IMAGE}:${VERSION}${NC}"
docker push "${FULL_IMAGE}:${VERSION}"

echo -e "${GREEN}Pushing ${FULL_IMAGE}:latest${NC}"
docker push "${FULL_IMAGE}:latest"

echo
echo -e "${GREEN}✓ Successfully pushed to GitHub Container Registry${NC}"
echo
echo -e "${YELLOW}Image available at:${NC}"
echo "  docker pull ${FULL_IMAGE}:${VERSION}"
echo "  docker pull ${FULL_IMAGE}:latest"
echo
echo -e "${YELLOW}To make the image public:${NC}"
echo "  Visit: https://github.com/users/${GIT_USER}/packages/container/${IMAGE_NAME}/settings"
