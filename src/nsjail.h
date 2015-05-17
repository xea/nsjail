#ifndef NSJAIL_H
#define NSJAIL_H

#define _GNU_SOURCE

#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/limits.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>

#define DEBUG(dbgmessage) 		(void) printf("DEBUG: %s\n", dbgmessage)
#define ERROR(errmessage) 		(void) printf("ERROR: %s\n", errmessage)
#define INFO(infomessage) 		(void) printf("INFO: %s\n", infomessage)

#define ERR_NO_EXECUTABLE NULL
#define ERR_AUTOMOUNT_FAILED -1
#define ERR_ENVIRONMENT_FAILED -1
#define ERR_CONFIG_NOT_INITIALISED -1

#define UID_ROOT 0
#define GID_ROOT 0

// These are also defined in linux/highuid.h
#define DEFAULT_OVERFLOWUID 65534
#define DEFAULT_OVERFLOWGID 65534

#define DEFAULT_CONTAINER_ROOT "/var/lib/libvirt/filesystems/vsandbox"

#define STACK_SIZE (1024 * 1024)

static char child_stack[STACK_SIZE];

typedef struct nsjail_automount_entry {
	char *type;
	char *source;
	char *target;
	char *options;
} nsjail_automount_entry_t;

typedef struct nsjail_conf {
	int automount_count;
	nsjail_automount_entry_t *automounts;
	char *container_root;
	char *exec_cmd;
	char **exec_argv;
	char *hostname;
	char *id_map;
	int verbosity;
	pid_t child_pid;
	int pipe_fd[2];
} nsjail_conf_t;

nsjail_conf_t * nsjail_default_config();
nsjail_conf_t * nsjail_parse_config(int argc, char **argv);

int nsjail_wait_signal(nsjail_conf_t *config);
int nsjail_send_signal(nsjail_conf_t *config);
int nsjail_map_ids(long pid, nsjail_conf_t *config);
int nsjail_enter_environment(nsjail_conf_t *config);
void nsjail_destroy_config(nsjail_conf_t *config);
int nsjail_automount(nsjail_conf_t *config);
void nsjail_lose_dignity();

#endif // NSJAIL_H
