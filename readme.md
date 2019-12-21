# Edge full-speed fuzzing


## Install Dyninst

[the branch](https://github.com/mxz297/dyninst/tree/rerewriting)

```
git clone https://github.com/mxz297/dyninst.git
cd dyninst
git checkout rerewriting
```
[install instructions]((https://github.com/mxz297/dyninst/tree/rerewriting))


## Install csi-afl

1. Downlaod source code.

2. Compile the source code.

change the 'Dyn_ROOT' in Makefile to your installed dyninst.

```
make clean && make all
```

3. set PATH
```
export PATH=$PATH:/path/to/your/csi-afl
```