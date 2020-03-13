#!/bin/bash

export PATH=$PATH:/home/xgzhu/apps/CSI-Fuzz/csi-afl
# export AFL_NO_UI=1 
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/home/xgzhu/apps/CSI-Fuzz/csi-afl
# $0: runfuzz.sh itself; $1: path to output directory
# $2: fuzzing seed dir;
# $3: path to target binary;  ${@:4}: parameters running targets
# bash runfuzz.sh ../outputs/becread1 ../target-bins/untracer_bins/binutils/readelf ../target-bins/untracer_bins/binutils/seed_dir/ -a @@

OUTDIR=${1}_csiafl
SEEDS=$2
TARGET=$3
FUZZTIME=$4
WITHDICT=$5
TIMEOUT=$6
PARAMS=`echo ${@:7}`


NAME=`echo ${TARGET##*/}`
# INSTNAME=${NAME}_inst


if [ "$WITHDICT"x = "nodict"x ]
then
    COMMD="./csi-afl -i $SEEDS -o ${OUTDIR}/out -t $TIMEOUT -- ${TARGET} $PARAMS"
else
    COMMD="./csi-afl -i $SEEDS -o ${OUTDIR}/out -x ${WITHDICT} -t $TIMEOUT -- ${TARGET} $PARAMS"
fi


(
    ${COMMD}
)&
sleep $FUZZTIME
# ctrl-c
ps -ef | grep "$COMMD" | grep -v 'grep' | awk '{print $2}' | xargs kill -2

rm ${OUTDIR}/CSI/${NAME}.oracle
rm ${OUTDIR}/CSI/${NAME}.trimmer
rm ${OUTDIR}/CSI/${NAME}.tracer
rm ${OUTDIR}/CSI/${NAME}.crasher

# #chmod 777 -R $OUTDIR
sleep 1

