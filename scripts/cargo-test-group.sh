#!/usr/bin/env zsh

# In order  to run this script you need:
# - toml-cli - it can be installed using pip install toml-cli.
# - yq - it can be installed with your package manager.
# - jq - is also yq dependencies, so you probably not need to install it manually.

directory=$(dirname $0)
set -e

# Returns list of members (Folders that contains Cargo.toml)
get_workspace_members() {
    # Get absolute path of worspace_root
    declare workspace_root="$(cd $directory/../; pwd)"
    # Find path to all Cargo.toml expect root, and ignore local .cargo registry cahe dirrectory
    for folder in $(find $workspace_root -path "$workspace_root/*/*" -name "Cargo.toml" | grep -v './.cargo/registry')
    do
        # Remove Cargo.toml from path, to better regexp.
        dirname $folder
    done
}

workspace_files=$(get_workspace_members)

# Find all members that meets regular expression $1
get_member_for_regexp() {
    echo $workspace_files | grep -e $1
}

#
# Implementation start there:
#

# Parse test-groups file, with pattern in $1
parse_file() {
    yq --compact-output --raw-output --exit-status $1 $directory/test-groups.yml 2>/dev/null
}

# Returns list of crates (by manifest path) for specifci test-group,
# that is sorted alphabetically, with filtered-out duplicates.
list_crates() {
    # Convert output to array, to avoid wildcard execution
    array_of_lines=("${(@f)$( parse_file ".\"$1\"[\"items\"][]" )}")
    packages=()
    for val in $array_of_lines
    do
        for item in $(get_member_for_regexp $val)
        do
            packages+=("$item"/Cargo.toml)
        done
    done
    # Remove duplicates
    echo "${packages[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' '
}
# List all features that should be activated for specific test-group.
list_features() {
    parse_file ".\"$1\"[\"features\"][]"
}

# Format features argument for cargo
format_features_arg() {
    features=()
    for arg in "$@"
    do
        features+=("--features")
        features+=($arg)
    done
    echo $features
}


items=($(list_crates "$1"))

if [[ -z "$items" ]]; then
    echo First param should be group name
    exit 1
fi
set +e

features=($(format_features_arg $(list_features "$1")))

# Run cargo test for specific target, with provided params
cargo_test () {
    cargo test --$1 --no-fail-fast -j8 --manifest-path $2 $3 "${@:4}" -- --test-threads=10
    
}

echo Running items: $items
for v in $items
do
    echo Running tests for $v
    set -x
    cargo check --all-targets --manifest-path $v
    # Run tests seperately for each target, to avoid fast fail,
    # if some of target cannot be compiled with toolchain.
    for target in bins tests examples
    do
        cargo_test $target $v $features "${@:2}"
    done
    # cargo test --bins --no-fail-fast -j8 --manifest-path $v $features "${@:2}" -- --test-threads=10
    # cargo test --tests --no-fail-fast -j8 --manifest-path $v $features "${@:2}" -- --test-threads=10
    set +x
done

