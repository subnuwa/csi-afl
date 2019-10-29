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

Instrument oracle:

`mkdir ../ouputs/readtest`

```
./CSIDyninst -i ../outputs/target-binaries/target-bins-afl/untracer_bins/binutils/readelf -o ../outputs/readtest/read.oracle -B ../outputs/readtest/oracle_addr_dir -O
```
Instrument tracer:
```
./CSIDyninst -i ../outputs/target-binaries/target-bins-afl/untracer_bins/binutils/readelf -o ../outputs/readtest/read.tracer -B ../outputs/readtest/tracer_addr_dir -T
```
run tracer:
```
../outputs/readtest/read.tracer -a ../outputs/target-binaries/target-bins-afl/untracer_bins/binutils/seed_dir/small_exec.elf
```
it's no problem.

re-instrument oracle:
```
./CSIReinst -i ../outputs/readtest/read.oracle -R ../outputs/target-binaries/target-bins-afl/untracer_bins/binutils/readelf -o ../outputs/readtest/read.oracle.new -B ../outputs/readtest/oracle_addr_dir/ -E ../outputs/readtest/tracer_addr_dir/ -O
```
run oracle.new:
```
../outputs/readtest/read.oracle.new -a ../target-bins/untracer_bins/binutils/seed_dir/small_exec.elf
```
segment fault.

