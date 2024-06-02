#define _GNU_SOURCE
#include <arpa/inet.h>
#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/if_link.h> // XDP_FLAGS_*
#include <net/if.h> /* if_nametoindex */

#include "params.h"
#include "tracepoint.h"

static int running = 1;

static void handle_int(int sig)
{
	running = 0;
}

int main(int argc, char *argv[])
{
	int ret;
	struct bpf_object *bpfobj;

	if (parse_args(argc, argv) != 0) {
		return EXIT_FAILURE;
	}

	/* Open eBPF binary file */
	bpfobj = bpf_object__open_file(context.bpf_bin, NULL);
	if (!bpfobj) {
		printf("Failed to open the BPF binary!\n    %s\n",
				context.bpf_bin);
		return EXIT_FAILURE;
	}

	/* Load all the BPF object to the kernel */
	ret = bpf_object__load(bpfobj);
	if (ret) {
		printf("Failed to load the BPF binary to the kernel\n");
		return EXIT_FAILURE;
	}

	struct bpf_program *prog = bpf_object__find_program_by_name(bpfobj, "handle_tp");
	if (prog == NULL) {
		fprintf(stderr, "Failed to find handle_tp program\n");
		return EXIT_FAILURE;
	}
	int pfd = bpf_program__fd(prog);
	ret = bpf_attach_tracepoint(pfd, "syscalls", "sys_enter_write");

	/* Wait for the user to SIGNAL the program */
	signal(SIGINT, handle_int);
	signal(SIGHUP, handle_int);
	printf("Ready!\n");
	printf("See the log at:\n  sudo cat /sys/kernel/debug/tracing/trace_pipe\n");
	printf("Hit Ctrl+C to stop\n");
	while (running) {
		sleep(3);
	}
	bpf_object__close(bpfobj);
	printf("Done!\n");
	return 0;
}
