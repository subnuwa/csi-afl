#!/bin/bash

export PATH=$PATH:/home/xgzhu/apps/CSI-Fuzz/csi-afl
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/home/xgzhu/apps/CSI-Fuzz/csi-afl

OUTDIR=${1}_csiafl
SEEDS=$2
TARGET=$3
FUZZTIME=$4
WITHDICT=$5
TIMEOUT=$6
PARAMS=`echo ${@:7}`


NAME=`echo ${TARGET##*/}`
# INSTNAME=${NAME}_inst

mkdir $OUTDIR
mkdir ${OUTDIR}/CSI
# get addr files
./CSIDyninst -i ${TARGET} -b ${OUTDIR}/CSI -P
# instrument oracle
./CSIDyninst -i ${TARGET} -o ${OUTDIR}/CSI/${NAME}.oracle -b ${OUTDIR}/CSI -F
#instrument tracer
./CSIDyninst -i ${TARGET} -o ${OUTDIR}/CSI/${NAME}.tracer -b ${OUTDIR}/CSI -T
# crasher
./CSIDyninst -i ${TARGET} -o ${OUTDIR}/CSI/${NAME}.crasher -b ${OUTDIR}/CSI -C
# instrument trimmer
./CSIDyninst -i ${TARGET} -o ${OUTDIR}/CSI/${NAME}.trimmer -b ${OUTDIR}/CSI -M

sleep 1