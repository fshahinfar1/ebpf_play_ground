CLANG=clang
LLC=llc
BPF_CFLAGS = -Wall \
			 -Wno-unused-value \
			 -Wno-pointer-sign \
			 -Wno-compare-distinct-pointer-types \
			 -O2 -emit-llvm -c -g
OUTPUT_DIR_BPF=./build/

default: ./build/loader ./build/trace.bpf.o
	@echo make compile
	@echo make run
	@echo make unload

compile: ./build/trace.bpf.o

run: ./build/loader
	@echo loading ... [requires bpftool]
	@# sudo bpftool prog load ./build/trace.bpf.o /sys/fs/bpf/trace_prog autoattach
	sudo ./build/loader -b ./build/trace.bpf.o
	@# @echo showing logs ...
	@# sudo cat /sys/kernel/debug/tracing/trace_pipe;

# unload:
# 	@echo unloading ...
# 	sudo rm /sys/fs/bpf/trace_prog


./build/loader: ./loader/*
	@if [ ! -d ./build/ ]; then mkdir ./build/; fi
	$(MAKE) -C ./loader

./build/trace.bpf.o: ./trace.bpf.c
	@echo compiling ...
	$(CLANG) --version
	@if [ ! -d ./build/ ]; then mkdir ./build/; fi
	LL_FILE=./build/trace.bpf.ll; \
	if [ -f $$LL_FILE ]; then rm $$LL_FILE; fi ; \
	$(CLANG) -S \
		-target bpf \
		-D __BPF_TRACING__ \
		$(BPF_CFLAGS) \
		-o $$LL_FILE  ./trace.bpf.c; \
	$(LLC) -mcpu=probe -march=bpf -filetype=obj -o ./build/trace.bpf.o $$LL_FILE

# Build libubpf.a
./lib/ubpf/vm/libubpf.a:
	if [ ! -d ./lib/ubpf/ ]; then git submodules update --init; fi
	$(MAKE) -C ./lib/ubpf/vm

./lib/libbpf/src/libbpf.a:
	if [ ! -d ./lib/libbpf/ ]; then git submodules update --init; fi
	BUILD_STATIC_ONLY=1 DESTDIR=./build/ PREFIX="" \
					  $(MAKE) -C ./lib/libbpf/src install -j
