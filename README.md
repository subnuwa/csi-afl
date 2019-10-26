# csi-afl
fuzzing with path sensitive instrumentation.

## How to use csi-afl
`git clone https://github.com/RosenZhu/csi-afl.git`

Change the `DYN_ROOT` in Makefile

`make clean && make all`

Environment variable.
```
export CSI_AFL_PATH=/path/to/csi-afl/
export PATH=$PATH:$CSI_AFL_PATH
```

