#!/bin/bash

FOLDER=results
TARGETS=("CVE-2010-2959" "CVE-2016-6187")
NUM=4
CORE_NUM=2
MEM_SIZE=2

for target in ${TARGETS[@]};
do
	res_path=$FOLDER/"$target"-idle-busy
	echo $target;
	echo $res_path
	python vuln_tester.py -c $target -n $NUM -r $res_path -C $CORE_NUM -m $MEM_SIZE -nl
done
