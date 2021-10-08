#! /bin/zsh

./stakers_to_json.sh m output.json
cat output.json | ./stakers_to_csv.sh input.csv
cat input.csv | ./convert_addr.sh output.csv