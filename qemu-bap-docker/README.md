QEMU with BAP tracewrap
=======================

Install podman, then build container:
```
make
```

Run shell in container:
```
make run
```

Inside the container, e.g. run an arm binary like this:
```
qemu-arm -L /usr/arm-linux-gnueabihf ./some_arm_bin
```
This will create a file `some_arm_bin.frames`.
