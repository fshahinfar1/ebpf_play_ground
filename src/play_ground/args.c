#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <net/if.h> /* if_nametoindex */

#include "include/args.h"
#include "include/log.h"

void usage(void)
{
	printf("Usage: playground [options]\n");
	printf("Options:\n");
	printf("  --help     -h:  path to bpf binary file\n");
	printf("  --binary  -b:  path to bpf binary file\n");
}

int parse_args(int argc, char **argv, struct arguments *args)
{
	int ret;
	enum opts {
		HELP = 500,
		BPF_BIN,
	};
	struct option long_opts[] = {
		{"help",     no_argument,       NULL, HELP},        /* h */
		{"bpf_bin",  required_argument, NULL, BPF_BIN},     /* b */
		/* End of option list ------------------- */
		{NULL, 0, NULL, 0},
	};

	/* Default values */
	args->ebpf_program_path = NULL;
	while(1) {
		ret = getopt_long(argc, argv, "hb:", long_opts, NULL);
		if (ret == -1)
			break;
		switch (ret) {
			case BPF_BIN:
			case 'b':
				args->ebpf_program_path = optarg;
				break;
			case HELP:
			case 'h':
				usage();
				return 1;
			default:
				usage();
				printf("Unknown argument '%s'!\n", argv[optind-1]);
				return 1;
		}
	}

	if (args->ebpf_program_path == NULL) {
		ERROR("Reuqire the path to eBPF bianry object\n");
		return 1;
	}
	return 0;
}
