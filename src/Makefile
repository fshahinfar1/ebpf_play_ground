CLANG=clang
LLC=llc
CFLAGS = -Wall
BPF_CFLAGS = -Wall \
			 -Wno-unused-value \
			 -Wno-pointer-sign \
			 -Wno-compare-distinct-pointer-types \
			 -O2 -emit-llvm -c -g
OUTPUT_DIR_BPF=./build/


default:
	@echo make compile
	@echo make run
	@echo make unload


compile:
	@echo compiling ...
	$(CLANG) --version
	if [ ! -d ./build/ ]; then mkdir ./build/; fi
	LL_FILE=./build/trace.bpf.ll; \
	if [ -f $$LL_FILE ]; then rm $$LL_FILE; fi ; \
	$(CLANG) -S \
		-target bpf \
		-D __BPF_TRACING__ \
		$(BPF_CFLAGS) \
		-o $$LL_FILE  ./trace.bpf.c; \
	$(LLC) -mcpu=probe -march=bpf -filetype=obj -o ./build/trace.bpf.o $$LL_FILE


run:
	@echo loading ... [requires bpftool]
	sudo bpftool prog load ./build/trace.bpf.o /sys/fs/bpf/trace_prog autoattach
	@echo showing logs ...
	trap "echo Done" INT; \
		sudo cat /sys/kernel/debug/tracing/trace_pipe;

unload:
	@echo unloading ...
	sudo rm /sys/fs/bpf/trace_prog
