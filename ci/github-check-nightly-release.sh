#!/bin/bash
#
# Check if our commit is latest
# Create and update release body, with link of latest release.
#

set -x
tag=$TAG
title="Velas nightly build"
commit_body="Commit: "
pipeline_build="Build: https://github.com/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID"
pattern="s/.*${commit_body}([a-f0-9\]+)(\\s|$).*/\\1/p"

our_commit=$(git rev-parse HEAD)

if [ -z "$our_commit" ]; then
    exit 1
fi
hub release
echo ${title} > release.md
echo "" >> release.md
echo ${commit_body}${our_commit} >> release.md
echo "" >> release.md
echo ${pipeline_build} >> release.md

release=$(hub release show ${tag})

if [ $? -eq 1 ]; then
    echo "No release for this tag was found, creating a new one"
    hub release create -p -F release.md ${tag}
    sleep 1
fi

release_commit=$(echo ${release} | sed -En "${pattern}")

if [ -z "$release_commit" ]; then
    release_commit=$our_commit
fi


if git merge-base --is-ancestor ${release_commit} HEAD; then
    echo "Commit is from our history, overriding the artifact"
    if [ "${release_commit}" != "${our_commit}" ]; then
        echo "Updating commit message"
        hub release delete ${tag}
        hub release create -p -F release.md ${tag}
    fi
    for file in velas-release-$TARGET.yml velas-install-init-$TARGET$EXE_EXT velas-release-$TARGET.tar.bz2; do
        hub release edit -a "$file" -m ''  ${tag}
    done
else
    echo "Looks like commit release commit ${release_commit} is from future, or from other conflicting branch."
    echo "Make sure to check https://github.com/$GITHUB_REPOSITORY/releases/tag/nightly release, and re-run job if needed."
    exit 1
fi
