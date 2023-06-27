#!/usr/bin/env zsh

# Use this script after `git merge` before resolving conflicts.

current_folder="$(dirname "$0")"
# echo "Reading version from $current_folder/solana-base"
BASE=$(cat $current_folder/solana-base)
echo "Solana base version is $BASE"

if [ -z "$GIT_MERGE_REMOTE" ];
then
    LOCAL=$(cat $current_folder/../.git/ORIG_HEAD)
    REMOTE=$(cat $current_folder/../.git/MERGE_HEAD)
else
    
    echo "Using GIT_MERGE_REMOTE variable to get merge head"
    REMOTE=$GIT_MERGE_REMOTE
    LOCAL=$(git rev-parse HEAD)
fi

echo "Velas commit is $LOCAL"
echo "Solana merging commit is $REMOTE"


velas_changes="$current_folder/velas-changes-$BASE-$LOCAL.txt"

remote_changes="$current_folder/velas-changes-remote-$REMOTE-$LOCAL.txt"
# echo "Forming list of files that differ in current branch from base version $velas_changes"
# 1. ignore docs/explorer/web3.js changes, use grep instead of pathspec exclude pattern because git is not handle it correctly
#   -  grep -Ev '^(docs|explorer|web3\.js)'
# 2. Use numstat with cut to save only file names - git diff --numstat | cut -f3-
# 3. If some file was renamed use only renamed part - sed -r 's/\{(.*) => (.*)\}/\2/'


git diff $LOCAL..$BASE --numstat | cut -f3- | sed -r 's/\{(.*) => (.*)\}/\2/' |  grep -Ev '^(docs|explorer|web3\.js)'  | sort  > $velas_changes

git diff $REMOTE..$BASE --numstat | cut -f3- | sed -r 's/\{(.*) => (.*)\}/\2/' |  grep -Ev '^(docs|explorer|web3\.js)' | sort > $remote_changes

pathspec_file="$current_folder/automerge-$BASE-$LOCAL.txt"

keep_ours_file="$current_folder/velas-rewrite"

# Velas use multiple repositories instead of big mono-repo:
# 1. velas-chain is repository only for blockchain related stuff.
# 2. web3-js mooved into https://github.com/velas/web3.js
# 3. Explorer mooved into https://github.com/velas/native-explorer
# 4. Docs are mooved into https://github.com/velas/velas-chain-docs
# 5. account-benches

# Removes js related stuf
git rm -rf explorer web3.js docs

# git checkout --ours --pathspec-from-file c

# Now save all files that was modified in remote but wasnt in our local
# Filter out changes from file that wasn't touched by velas changes

for file in $(comm -23 $remote_changes $velas_changes)
do
    echo "Adding file $file from remote"
    # its okay that this commands can not find some files, because its can be marked as already fixed
    git checkout --theirs -- $file
    git add $file
done

# Old version with git pathspecs
# sed -e 's/^/\:\^/' $velas_changes > $pathspec_file

# if git checkout --theirs --pathspec-from-file $pathspec_file; then
#     # If command succeed then no removed files found in remote branch
# else
#     # if fails
#     # 1. Collect list of failed files

#     git checkout --theirs --pathspec-from-file $pathspec_file |& awk '{ print $3 }' | sed "s/[«|»]/'/g"  > "$current_folder/remote-removed.txt"

#     # 2. Explicitly remove files that was already removed.
#     cat "$current_folder/remote-removed.txt" | xargs git rm
#     # 3. Repeat checkout of remaining files
#     git checkout --theirs --pathspec-from-file $pathspec_file cat
# fi

# git add --pathspec-from-file $pathspec_file