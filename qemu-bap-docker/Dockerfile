FROM ubuntu:16.04

RUN sed -i 's/^# *deb-src/deb-src/g' /etc/apt/sources.list
RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive TZ=Etc/UTC apt-get -y install tzdata
RUN apt-get --no-install-recommends -y build-dep qemu
RUN apt-get -y install autoconf libtool protobuf-c-compiler libprotobuf-c-dev git python opam \
	gcc-arm-linux-gnueabi \
	gcc-arm-linux-gnueabihf \
	gcc-aarch64-linux-gnu
RUN opam init -a
RUN opam install -y piqi

RUN mkdir /build
WORKDIR /build
RUN git clone https://github.com/BinaryAnalysisPlatform/bap-frames.git && \
	cd bap-frames && git checkout c9f957492c13106171b04914dab4badc9ff5bcad && cd .. && \
	git clone https://github.com/BinaryAnalysisPlatform/qemu.git && \
	cd qemu && git checkout a9fb4c6d055a5825cd886bc02e788af5278638ed

WORKDIR /build/qemu
RUN ./configure --prefix=/usr --with-tracewrap=../bap-frames --target-list="arm-linux-user i386-linux-user x86_64-linux-user mips-linux-user" --disable-werror
RUN eval $(opam config env) && make -j8
RUN make install

WORKDIR /
CMD /bin/bash
