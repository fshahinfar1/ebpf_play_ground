CLANG = clang
LLC   = llc
OUTDIR  = ./build
SOURCES = $(wildcard *.c)
OBJECTS = $(foreach program, $(SOURCES),$(OUTDIR)/${program:.c=.o})
# $(info $(SOURCES))
# $(info $(OBJECTS))


BPF_CFLAGS = -Wall \
			 -Wno-unused-value \
			 -Wno-pointer-sign \
			 -Wno-compare-distinct-pointer-types \
			 -I ../play_ground/interface \
			 -O2 -emit-llvm -c -g


all: $(OBJECTS)

$(OUTDIR)/%.o: %.c
	@echo "compiling $<   to  $@"
	@if [ ! -d ./build/ ]; then mkdir ./build/; fi
	LL_FILE=./build/$<.ll; \
	if [ -f $$LL_FILE ]; then rm $$LL_FILE; fi ; \
	$(CLANG) -S \
		-target bpf \
		-D __BPF_TRACING__ \
		$(BPF_CFLAGS) \
		-o $$LL_FILE  $<; \
	$(LLC) -mcpu=probe -march=bpf -filetype=obj -o $@ $$LL_FILE
