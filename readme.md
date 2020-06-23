# Overview
Remove instrumentation on the binary file using libelf.

CSI-Fuzz aims to fuzz binaries efficiently, which uses the idea of full-speed fuzzing. 

The current version is for non-PIE binaries. It's tested on Linux 18.04, 64bit.

## Install Dyninst
We use Dyninst to instrument target binaries. So firstly, install Dyninst [the branch](https://github.com/mxz297/dyninst).

[Instruction for installing Capstone, libunwind and Dyninst](https://github.com/iu-parfunc/ShadowGuard/blob/master/bazel.sh); 

For the branch of Dyninst, use `csifuzz`.

```
mkdir dyninst101
cd dyinst101
root_dir=`pwd`
```

### Install capstone

```
git clone https://github.com/mxz297/capstone.git thirdparty/capstone
cd thirdparty/capstone
git checkout access-fixes
cd $root_dir
cd thirdparty/capstone
mkdir install
mkdir -p build
cd build

# Configure
cmake -DCMAKE_INSTALL_PREFIX=`pwd`/../install ..

# Install
nprocs=`cat /proc/cpuinfo | awk '/^processor/{print $3}' | wc -l`
make -j "$(($nprocs / 2))" install
```

### Install libunwind
```
cd $root_dir
git clone  https://github.com/mxz297/libunwind.git thirdparty/libunwind
cd thirdparty/libunwind
mkdir install
# Configure
./autogen.sh
./configure --prefix=`pwd`/install --enable-cxx-exceptions

# Install
nprocs=`cat /proc/cpuinfo | awk '/^processor/{print $3}' | wc -l`
make -j "$(($nprocs / 2))" install
```

### Install Dyninst
```
cd $root_dir
git clone https://github.com/mxz297/dyninst.git thirdparty/dyninst-10.1.0
cd thirdparty/dyninst-10.1.0/
git checkout csifuzz
cd $root_dir
cd thirdparty/dyninst-10.1.0/
mkdir install
mkdir -p build
cd build

# Configure
cmake -DLibunwind_ROOT_DIR=`pwd`/../../libunwind/install -DCapstone_ROOT_DIR=`pwd`/../../capstone/install/ -DCMAKE_INSTALL_PREFIX=`pwd`/../install -G 'Unix Makefiles' ..

nprocs=`cat /proc/cpuinfo | awk '/^processor/{print $3}' | wc -l`
make -j "$(($nprocs / 2))"
# Build
#   Dyninst build tends to succeed with a retry after an initial build failure.
#   Cover that base with couple of retries.

make install
```

## Set up ENVs
```
export DYNINST_INSTALL=/path/to/dyninst/build/dir
export CSIFUZZ_PATH=/path/to/csi-fuzz

export DYNINSTAPI_RT_LIB=$DYNINST_INSTALL/lib/libdyninstAPI_RT.so
export LD_LIBRARY_PATH=$DYNINST_INSTALL/lib:$CSIFUZZ_PATH
export PATH=$PATH:$CSIFUZZ_PATH
```

## Install libelf
    sudo apt install libelf-dev

## Install CSIFuzz
Enter the folder csi-afl.
Change DYN_ROOT in makefile accordingly. Then
```
make clean && make all
```

## Run fuzzing

Fuzzing the target binary.

```
./csi-afl -i /path/to/seeds -o /path/to/output -t 500 -- /path/to/target/binary [params]
```

