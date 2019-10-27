# csi-afl
fuzzing with path sensitive instrumentation.

## How to use csi-afl
downloads the target binaries:
```
mkdir outputs
cd outputs
git clone https://github.com/RosenZhu/target-binaries.git
cd target-binaries
tar -xvf target-bins-seeds.tar
cd ../..

``` 

download csi-afl:
```
git clone https://github.com/RosenZhu/csi-afl.git
cd csi-afl
```

Change the `DYN_ROOT` in Makefile to /path/to/your/dyninst/build/

`make clean && make all`

Environment variable.
```
export CSI_AFL_PATH=/path/to/csi-afl/
export PATH=$PATH:$CSI_AFL_PATH
```

run csi-afl:

`./csi-afl -i ../outputs/target-binaries/target-bins-afl/untracer_bins/tcpdump/seed_dir/ -o ../outputs/tcptest -t 500 -- ../outputs/target-binaries/target-bins-afl/untracer_bins/tcpdump/tcpdump -nr @@`

This will manifest the problem.

When using the CSIReinst seperately, the problem doesn't show:

`./CSIReinst -i ../outputs/tcptest/CSI/tcpdump.oracle_old -R ../outputs/target-binaries/target-bins-afl/untracer_bins/tcpdump/tcpdump -o ../outputs/tcptest/CSI/tcpdump.oracle -B ../outputs/tcptest/CSI/tcpdump_oracle_addr/ -E ../outputs/tcptest/CSI/tcpdump_tracer_addr/ -O`