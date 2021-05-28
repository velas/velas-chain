# |source| this file
#
# Common utilities shared by other scripts in this directory
#
# The following directive disable complaints about unused variables in this
# file:
# shellcheck disable=2034
#

# shellcheck source=net/common.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. || exit 1; pwd)"/net/common.sh

prebuild=
if [[ $1 = "--prebuild" ]]; then
    prebuild=true
fi

if [[ $(uname) != Linux ]]; then
    # Protect against unsupported configurations to prevent non-obvious errors
    # later. Arguably these should be fatal errors but for now prefer tolerance.
    if [[ -n $SOLANA_CUDA ]]; then
        echo "Warning: CUDA is not supported on $(uname)"
        SOLANA_CUDA=
    fi
fi

if [[ -n $USE_INSTALL || ! -f "$SOLANA_ROOT"/Cargo.toml ]]; then
    velas_program() {
        declare program="$1"
        if [[ -z $program ]]; then
            printf "velas"
        else
            printf "velas-%s" "$program"
        fi
    }
else
    velas_program() {
        declare program="$1"
        declare crate="$program"
        if [[ -z $program ]]; then
            crate="cli"
            program="velas"
        else
            program="velas-$program"
        fi
        
        declare prefix=$2;
        if [ "$crate" = "cli" ]; then
            prefix="solana"
        fi
        
        if [[ -r "$SOLANA_ROOT/$crate"/Cargo.toml ]]; then
            if [[ "$prefix" == "" ]]; then
                maybe_package="--package velas-$crate"
            else
                maybe_package="--package $prefix-$crate"
            fi
        fi
        
        if [[ -n $NDEBUG ]]; then
            maybe_release=--release
        fi
        declare manifest_path="--manifest-path=$SOLANA_ROOT/$crate/Cargo.toml"
        printf "cargo $CARGO_TOOLCHAIN run $manifest_path $maybe_release $maybe_package --bin %s %s -- " "$program"
    }
    
fi

velas_bench_tps=$(velas_program bench-tps)
velas_faucet=$(velas_program faucet solana)
velas_validator=$(velas_program validator)
velas_validator_cuda="$velas_validator --cuda"
velas_genesis=$(velas_program genesis solana)
velas_gossip=$(velas_program gossip)
velas_keygen=$(velas_program keygen)
velas_ledger_tool=$(velas_program ledger-tool)
velas_cli=$(velas_program)

export RUST_BACKTRACE=1

default_arg() {
    declare name=$1
    declare value=$2
    
    for arg in "${args[@]}"; do
        if [[ $arg = "$name" ]]; then
            return
        fi
    done
    
    if [[ -n $value ]]; then
        args+=("$name" "$value")
    else
        args+=("$name")
    fi
}

replace_arg() {
    declare name=$1
    declare value=$2
    
    default_arg "$name" "$value"
    
    declare index=0
    for arg in "${args[@]}"; do
        index=$((index + 1))
        if [[ $arg = "$name" ]]; then
            args[$index]="$value"
        fi
    done
}
