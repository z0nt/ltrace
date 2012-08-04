#include <sys/ptrace.h>

typedef struct {
	int valid;
	struct reg regs;
	unsigned int func_arg[6];
	unsigned int sysc_arg[6];
} proc_archdep;
