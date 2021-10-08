#! /bin/zsh

get_first_line() {
    head -n1 <<< $*
}

remove_quote() {
    tr -d '"' <<< $*
}

if [ -z "$1" ]
then
    echo "Type output file name as first argument."
    exit 1
fi

echo Reading stakers json input
echo Writing csv output to $1

cat | jq -r '(.[1] | keys_unsorted) as $keys | $keys, map([.[ $keys[] ]])[] | @csv' >$1