rz-tracetest
============

This is a testing tool for the correctness of RzIL lifters, which compares
executions of instructions from a real trace against the result of executing
the same instructions in the RzIL VM.

The idea is very similar to
[bap-veri](https://github.com/BinaryAnalysisPlatform/bap-veri) and it uses the
same trace format, called
[bap-frames](https://github.com/BinaryAnalysisPlatform/bap-frames).

Trace sources
-------------

The following sources are currently known to produce meaningful results with
rz-tracetest:

* [QEMU](https://github.com/BinaryAnalysisPlatform/qemu) Patched for the BAP
  project. Specifically useful for ARM and potentially later x86 too.
* [VICE](https://github.com/rizinorg/vice) Patched VICE emulator for testing
  6502.
* [SameBoy](https://github.com/rizinorg/SameBoy) Patched Game Boy emulator for
  testing gb (sm83)

Other sources which have not been tested with rz-tracetest specifically yet:

* [bap-pintraces](https://github.com/BinaryAnalysisPlatform/bap-pintraces) using
  Intel Pin. Useful for x86, but alas Pin is proprietary.

Building
--------

First, install rizin and make sure the bap-frames submodule is up to date:
```
git submodule update --init
```

Afterwards install the build dependencies:
```
sudo apt install libprotobuf-dev protobuf-compiler
```

Then:
```
cd rz-tracetest
# -DCMAKE_BUILD_TYPE=Debug for debugging, -DENABLE_ASAN=1 for ASAN
cmake -Bbuild -GNinja
ninja -C build
```

This will build the `rz-tracetest` executable in `build/`.

Usage
-----

After obtaining a trace, run `rz-tracetest` on it. It will execute all
contained instructions and print mismatches between the trace and RzIL if found:
```
rz-tracetest mytrace.frames
```

Building with Nix
-----------------

### Prerequisites

- [Nix](https://nixos.org/download) installed with flakes support enabled

### Quick Start

To enter a development environment with all dependencies:

```bash
nix develop
```

This command sets up a shell with:
- CMake and Ninja build tools
- Protobuf compiler and development libraries
- OCaml with Piqi (for protocol buffer generation)
- Rizin (the main binary analysis framework)

### Building

Once in the development shell:

```bash
cmake -B build -S rz-tracetest -GNinja
cmake --build build
```

### Building without entering a shell

To build directly without entering the development environment:

```bash
nix build
```

The resulting executable will be available at `./result/bin/rz-tracetest`.

The pinned Rizin dependency can also be built independently:

```bash
nix build .#rizin
```

### Running with Nix

To run `rz-tracetest` directly with Nix:

```bash
nix run . -- mytrace.frames
```

### Flake outputs

The flake provides the following:

- **packages.rizin**: The pinned Rizin development revision
- **packages.rz-tracetest**: The compiled `rz-tracetest` executable
- **packages.default**: Alias for `rz-tracetest`
- **devShells.default**: Development shell with all build dependencies
- **formatter**: `nixfmt-tree` for Nix code formatting

### Updating Rizin

The pinned revision and fixed-output hashes are stored together in
`nix/rizin/checksum.json`. From the repository root, update to the current
Rizin `dev` branch with:

```bash
./nix/rizin/update.sh
```

To update to a specific full commit SHA instead:

```bash
./nix/rizin/update.sh <commit>
```

The updater recalculates the source and Meson dependency hashes, then builds
both Rizin and `rz-tracetest`. It restores the previous checksum file if
validation fails and does not create a commit.

Adjustments to specific Archs/Sources/...
-----------------------------------------

In many cases, data given in the trace does not directly map to Rizin. For
example, the arch plugin name must be determined and register names might
differ.
These adjustments, which are in general specific to a certain architecture or
trace source, are performed by implementing the `TraceAdapter` interface. See
`VICETraceAdapter` for an example.

Trace format
------------

The trace consists of three parts: the header,
a table of contents (TOC) holding the frame entries, and an index into the TOC.

Each frame entry starts with the size of the frame, followed by the actual frame data.
A fixed number of frame entries are considered one _entry_ in the TOC.

The TOC index is stored at the end.

[!IMPORTANT]
The last TOC entry might holds less than `m` frames.

For specifics about the frame contents, please check the definitions in the [piqi](piqi/) directory.

**Format**

| Offset | Type | Field | Trace section |
|--------|------|-------|------|
|    0x0    | uint64_t | magic number (7456879624156307493LL) | Header begin |
|    0x8    | uint64_t | trace version number | |
|    0x10    | uint64_t | frame_architecture | |
|    0x18    | uint64_t | frame_machine, 0 for unspecified. | |
|    0x20    | uint64_t | n = total number of frames in trace. | |
|    0x28    | uint64_t | T = offset to TOC index. | |
|    0x30    | uint64_t | sizeof(frame_0) | TOC begin  |
|    0x38    | meta_frame   | frame_0 | |
|    0x40    | uint64_t     | sizeof(frame_1) | |
|    0x48    | type(frame_1) | frame_1 | |
|    ...     | ...          | ... | |
|    T-0x10  | uint64_t     | sizeof(frame_n-1) | |
|    T-0x8   | type(frame_n-1) | frame_n-1 | |
|    T+0     | uint64_t     | m = number of frames per TOC entry | TOC index begin |
|    T+0x8   | uint64_t     | offset toc_entry(0) | |
|    T+0x10  | uint64_t     | offset toc_entry(1) | |
|    ...     | ...          | ... | |
|    T+0x8+(0x8*ceil(n/m))   | uint64_t     | offset toc_entry(ceil(n/m)) | |

Works with TCG tracing plugin
-----------------------------

| Architecture | Works with TCG plugin |
|--------------|-----------------------|
| Hexagon      | Yes                   |
| PPC          | No - register and endian mismatches |
| ARM          | No - Cannot trace cpu modes |
| M68K         | Yes - requires a nonzero M68K frame machine value |

M68K traces are 32-bit and big-endian. Supported frame machine values select
Rizin CPUs `68000`, `68010`, `68020`, `68030`, `68040`, `68060`, `cfv2`, or
`cfv4e`. QEMU `m5206` and `m5208` select `cfv2`; `cfv4e` and the synthetic
`any` model select `cfv4e`. Unknown and unspecified M68K machine values are
rejected. QEMU's 96-bit floating-point register representation is normalized
against Rizin's 80-bit representation with the QEMU alignment padding fixed
to zero.


## Troubleshooting

### Build Errors
**Protobuf Variable Shadowing Error (`target` does not name a type)**

When building on rolling-release Linux distros (like Arch Linux) providing modern Protocol Buffer installations (`protoc` version 22+ / v25+ / v34+), compilation of the generated C++ files may fail with errors resembling:

```zsh
error: ‘target’ does not name a type
   const target& this_ = *this;
error: ‘this_’ was not declared in this scope
   this_.CheckHasBitConsistency();
```

**Cause:**
>Starting with the release of Protocol Buffers v22.x in early 2023, Google introduced significant, breaking changes to the C++ code generator and runtime APIs.The primary driver for these API modifications was Google's decision to drop support for C++11, adopt C++14 as the new baseline, and explicitly introduce support for C++20 keywords

Stable releases of distros like Ubuntu or Debian pin older versions of Protobuf (`v3.x`), which generate legacy C++ code that does not encounter this namespace collision. Rolling-release distributions like Arch Linux install the latest versions (`v34.x`), exposing the bug.

**Solutions**
1. **If you use Nix:** Follow [Building with Nix](#building-with-nix). The Nix Flake automatically provisions an isolated, compatible legacy toolchain.

2. **If not using Nix**
   - Ensure if your host environment has zero dependencies relying on modern Protobuf using `pactree -r protobuf`
   - If safe to proceed, use the `downgrade` tool to downgrade protobuf version from `34.x` to any version before `21.x`. Run `sudo downgrade protobuf` and select `3.20.1`. 
   - Perform a clean build 
      ```zsh  
      rm -rf build/
      cmake -Bbuild -GNinja
      ninja -C build
      ```
