#include <playground_helpers.h>


int bpf_prog(void *ctx)
{
	ubpf_print("hello world\n");
	return 0;
}
