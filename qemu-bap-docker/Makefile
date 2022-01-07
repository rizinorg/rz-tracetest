
PODMAN=podman
RUN_ARGS="-v`pwd`/..:/il-test"

all: build

.PHONY: build
build:
	${PODMAN} build -t bap-qemu .

.PHONY: run
run:
	${PODMAN} run --rm -it ${RUN_ARGS} bap-qemu
