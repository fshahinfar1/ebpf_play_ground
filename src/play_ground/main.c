#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "include/args.h"
#include "include/log.h"
#include "include/vm.h"

struct arguments args;


int main(int argc, char *argv[])
{
	int ret;
	struct ubpf_vm *vm;

	ret = parse_args(argc, argv, &args);
	if (ret) {
		return EXIT_FAILURE;
	}

	ret = setup_ubpf_engine(args.ebpf_program_path, &vm);
	if (ret) {
		return EXIT_FAILURE;
	}

	run_vm(vm, NULL, 0);

	ubpf_destroy(vm);
	return 0;
}
