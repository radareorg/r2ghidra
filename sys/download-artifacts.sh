#!/bin/sh

set -e

WORKFLOWS="ci.yml"
DESTDIR="dist/artifacts"
LIMIT=100

if ! command -v gh &> /dev/null; then
    echo "GitHub CLI (gh command) could not be found"
    exit 1
fi

cd `dirname $PWD/$0`/..

COMMIT="$1" # Optional
if [ -z "${COMMIT}" ]; then
  COMMIT=`git rev-parse HEAD`
  echo "Detected commit: ${COMMIT}"
fi

echo "Removing old dist artifacts..."
rm -Rf "${DESTDIR}"

for WORKFLOW in $WORKFLOWS; do
  echo "Looking for ${COMMIT} in ${WORKFLOW} last ${LIMIT} executions..."
  RUN_ID=`gh run list --workflow "${WORKFLOW}" --limit "${LIMIT}" --json "databaseId,headSha" --jq '.[] | select(.headSha=="'"${COMMIT}"'") | .databaseId'`
  if [ -n "${RUN_ID}" ]; then
    echo "Found run id ${RUN_ID} for ${WORKFLOW} workflow."
    echo "Downloading all artifacts..."
    gh run download "${RUN_ID}" --dir "${DESTDIR}"
  else
    echo "No execution found for ${COMMIT} in the last ${LIMIT} executions of ${WORKFLOW} workflow."
    exit 1
  fi
done

echo "Artifacts downloaded:"
find "${DESTDIR}" -type f

# Move plugin ZIPs up from nested dist/macos subdirs into the artifact root
for d in "${DESTDIR}"/macos-pkg-*; do
  if [ -d "$d/dist/macos" ]; then
    mv "$d/dist/macos/"*.zip "$d/" 2>/dev/null || true
    rm -rf "$d/dist"
  fi
done

echo "Flattened plugin ZIPs:"
find "${DESTDIR}" -type f -name '*.zip'
