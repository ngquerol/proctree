#include <errno.h>
#include <libproc.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/sysctl.h>

typedef struct proc_node proc_node_t;

proc_node_t *proc_tree_create(pid_t root_pid);

void proc_tree_destroy(proc_node_t **node);

void proc_tree_print(proc_node_t const *node);
