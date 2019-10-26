# csi-afl
fuzzing with path sensitive instrumentation.

## How to use csi-afl
downloads the target binaries
```
mkdir outputs
cd outputs
git clone https://github.com/RosenZhu/target-binaries.git
cd target-binaries
tar -xvf target-bins-seeds.tar
cd ../..

``` 

`git clone https://github.com/RosenZhu/csi-afl.git`

`cd csi-afl`
Change the `DYN_ROOT` in Makefile to /path/to/your/dyninst/build/

`make clean && make all`

Environment variable.
```
export CSI_AFL_PATH=/path/to/csi-afl/
export PATH=$PATH:$CSI_AFL_PATH
```

Instrument a binary

`./CSIDyninst -i ../outputs/target-binaries/target-bins-afl/untracer_bins/tcpdump/tcpdump -o ../outputs/tcpinst -B ../outputs/tcpdir -O`

Re-instrument the binary

`./CSIReinst -i ../outputs/tcpinst -R ../outputs/target-binaries/target-bins-afl/untracer_bins/tcpdump/tcpdump -o ../outputs/tcpre -B ../outputs/tcpdir -E ../outputs/tcpdir/ -O`