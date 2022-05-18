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

* [VICE](https://github.com/rizinorg/vice) Patched VICE emulator for testing
  6502.
* [QEMU](https://github.com/BinaryAnalysisPlatform/qemu) Patched for the BAP
  project. Specifically useful for ARM and potentially later x86 too.

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
sudo apt install libprotobuf-dev protobuf-compile
```

Then:
```
cd rz-tracetest
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

Adjustments to specific Archs/Sources/...
-----------------------------------------

In many cases, data given in the trace does not directly map to Rizin. For
example, the arch plugin name must be determined and register names might
differ.
These adjustments, which are in general specific to a certain architecture or
trace source, are performed by implementing the `TraceAdapter` interface. See
`VICETraceAdapter` for an example.
