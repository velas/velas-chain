#! /bin/zsh


if [ -z "$1" ]
then
    echo "Expected network url to be first param."
    exit 1
fi

if [ -z "$2" ]
then
    echo "Type output file name as second argument."
    exit 1
fi

./target/release/velas -u $1 stakes --output json-compact > $2