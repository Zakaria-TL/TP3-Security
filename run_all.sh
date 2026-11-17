#!/usr/bin/env bash
# usage: ./run_all.sh path/to/train_test_network.csv
set -e
python3 part_a_anonymization.py --data "$1" --sample 150000
python3 part_b_ssi.py
