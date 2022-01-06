FROM ubuntu:20.04

RUN sed -i 's/^# *deb-src/deb-src/g' /etc/apt/sources.list
RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive TZ=Etc/UTC apt-get -y install tzdata
RUN apt-get --no-install-recommends -y build-dep qemu
RUN apt-get -y install autoconf libtool protobuf-c-compiler libprotobuf-c-dev git python opam
RUN opam init -a --disable-sandboxing
RUN opam install -y piqi

RUN mkdir /build
WORKDIR /build
RUN git clone https://github.com/BinaryAnalysisPlatform/bap-frames.git && \
	git clone https://github.com/BinaryAnalysisPlatform/qemu.git

WORKDIR /build/qemu
RUN ./configure --prefix=/usr --with-tracewrap=../bap-frames --target-list="arm-linux-user i386-linux-user x86_64-linux-user mips-linux-user" --disable-werror
RUN eval $(opam env) && make
RUN make install

CMD /bin/bash
