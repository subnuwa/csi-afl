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

run csi-afl to test readelf:

```
./csi-afl -i ../outputs/target-binaries/target-bins-afl/untracer_bins/binutils/seed_dir/ -o ../outputs/readtest -t 500 -- ../outputs/target-binaries/target-bins-afl/untracer_bins/binutils/readelf -a @@
```



This will manifest the problem.

Then using the CSIReinst seperately, the problem doesn't show:

```
./CSIReinst -i ../outputs/readtest/CSI/readelf.oracle_old  -R ../outputs/target-binaries/target-bins-afl/untracer_bins/binutils/readelf -o ../outputs/readtest/CSI/readelf.oracle.new -B ../outputs/readtest/CSI/readelf_oracle_addr/ -E ../outputs/readtest/CSI/readelf_tracer_addr/ -O
```
