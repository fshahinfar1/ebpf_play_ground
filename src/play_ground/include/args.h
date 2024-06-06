#ifndef __ARGS_H
#define __ARGS_H
struct arguments {
	char *ebpf_program_path;
};
/* The variable is defined in main */
extern struct arguments args;

int parse_args(int argc, char **argv, struct arguments *args);
#endif
