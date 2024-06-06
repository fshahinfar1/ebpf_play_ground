CC = clang

HEADERS = $(wildcard include/*.h)
SOURCES = $(wildcard *.c)

CFLAGS = -Wall -O2 -g \
		 -I ../lib/ubpf/vm/inc \
		 -I ../lib/libbpf/src/build/include/

LDFLAGS = -L ../lib/ubpf/vm/ -l:libubpf.a \
		  -L ../lib/libbpf/src/build/lib64/ -l:libbpf.a -lelf -lz

playground: $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -o playground $(SOURCES) $(LDFLAGS)
