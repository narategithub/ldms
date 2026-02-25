#!/bin/bash

NAMES=(
	samp{1..4}
	agg{11,12,21}
)

for N in "${NAMES[@]}" ; do
	CMD="ldmsd -c ${N}.conf -n ${N}"
	echo "CMD: ${CMD}"
	${CMD} &
done
