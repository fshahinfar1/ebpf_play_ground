#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <net/if.h> /* if_nametoindex */
#include "params.h"


struct context context;

void usage(void)
{
	printf("Usage: loader [options]\n");
	printf("Options:\n");
	printf("  --help     -h:  path to bpf binary file\n");
	printf("  --bpf_bin  -b:  path to bpf binary file\n");
	/* printf("  --bpf_prog -p:  name of bpf program to load (can suply multiple)\n"); */ 
	/* printf("  --iface:   -i:  the interface to use for TC or XDP program\n"); */
	/* printf("  --port     -P:  the destination port (for connection monitor)\n"); */
	/* printf("  --xdp:          load XDP program on given interface\n"); */
	/* printf("  --gxdp:         load XDP program in generic mode\n"); */
	/* printf("  --tc:           load TC program on ingress of given interface\n"); */
	/* printf("  --skskb:        load SK_SKB program\n"); */
}

static int get_default_cgroup_fd(void)
{
	/* TODO: Get the CGROUP name from the user */
	int fd;
	fd = open("/sys/fs/cgroup/user.slice", O_DIRECTORY | O_RDONLY);
	if (fd < 0) {
		fd = open("/sys/fs/cgroup/unified/", O_DIRECTORY | O_RDONLY);
	}
	return fd;
}

int parse_args(int argc, char *argv[])
{
	int i;
	int ret;
	int count_prog = 0;
	int ifindex = 0;
	int ifindex_req_num = 0;
	struct attach_request *req;
	enum opts {
		HELP = 500,
		BPF_BIN,
		/* BPF_PROG, */
		DEST_PORT,
		XDP_FLAG,
		TC_FLAG,
		SKSKB_FLAG,
		IFACE,
		XDP_G_FLAG,
	};

	struct option long_opts[] = {
		{"help",     no_argument,       NULL, HELP},        /* h */
		{"bpf_bin",  required_argument, NULL, BPF_BIN},     /* b */
		/* {"bpf_prog", required_argument, NULL, BPF_PROG},    /1* p *1/ */
		{"port",     required_argument, NULL, DEST_PORT},   /* P */
		{"iface",    required_argument, NULL, IFACE},       /* i */
		{"skskb",    required_argument, NULL, SKSKB_FLAG},
		{"xdp",      required_argument, NULL, XDP_FLAG},
		{"gxdp",     required_argument, NULL, XDP_G_FLAG},
		{"tc",       required_argument, NULL, TC_FLAG},
		/* End of option list ------------------- */
		{NULL, 0, NULL, 0},
	};


	/* Default values */
	context.port = 8080;
	context.bpf_bin = NULL;
	context.cgroup_fd = get_default_cgroup_fd();

	while(1) {
		ret = getopt_long(argc, argv, "hb:p:P:i:", long_opts, NULL);
		if (ret == -1)
			break;
		switch (ret) {
			case BPF_BIN:
			case 'b':
				context.bpf_bin = optarg;
				break;
			case 'p':
				printf("Error: -p is depricated!\n");
				return 1;
			case DEST_PORT:
			case 'P':
				context.port = atoi(optarg);
				break;
			case IFACE:
			case 'i':
				/* overwrite the last programs interface and
				 * use for the next programs
				 * */
				ifindex = if_nametoindex(optarg);
				if (ifindex == 0) {
					printf("Failed to get interface index!\n");
					return 1;
				}
				for (i = ifindex_req_num; i < count_prog; i++) {
					context.bpf_prog[i].ifindex = ifindex;
				}
				ifindex_req_num = count_prog;
				break;
			case XDP_FLAG:
				req = &context.bpf_prog[count_prog++];
				req->prog_name = optarg;
				req->bpf_hook = XDP;
				req->ifindex = ifindex;
				break;
			case XDP_G_FLAG:
				req = &context.bpf_prog[count_prog++];
				req->prog_name = optarg;
				req->bpf_hook = GXDP;
				req->ifindex = ifindex;
				break;
			case TC_FLAG:
				req = &context.bpf_prog[count_prog++];
				req->prog_name = optarg;
				req->bpf_hook = TC;
				req->ifindex = ifindex;
				break;
			case SKSKB_FLAG:
				req = &context.bpf_prog[count_prog++];
				req->prog_name = optarg;
				req->bpf_hook = SK_SKB;
				req->ifindex = ifindex;
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
	context.count_prog = count_prog;

	if (context.bpf_bin == NULL) {
		printf("Should define the path to the BPF binary (--bpf_bin)\n");
		return 1;
	}

	/* if (count_prog < 1) { */
	/* 	printf("Should provided at least one program (--bpf_prog)\n"); */
	/* 	return 1; */
	/* } */

	for (uint32_t i = 0; i < count_prog; i++) {
		req = &context.bpf_prog[i];
		if (req->bpf_hook == SK_SKB) {
			/* SK_SKB does not require an interface */
			continue;
		}
		if (req->ifindex <= 0) {
			printf("You need to specify the target network interface (--iface)\n");
			return 1;
		}
	}
	return 0;
}
