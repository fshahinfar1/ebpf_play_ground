CC = clang
CFLAGS = -g -Wall -O2
LDFLAGS = -lbpf

../build/loader: ./loader.c ./params.c
	@if [ ! -d ../build/ ]; then mkdir ../build/; fi
	$(CC) $(CFLAGS) -o $@ ./loader.c ./params.c $(LDFLAGS)
