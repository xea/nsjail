#ifndef NSJAIL_H
#define NSJAIL_H

#define _GNU_SOURCE

#include <grp.h>
#include <pwd.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/capability.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <linux/limits.h>

#include <libconfig.h>

#ifndef TRUE
#define TRUE 1
#endif 

#ifndef FALSE
#define FALSE 0
#endif

#ifndef NS_ERROR
#define NS_ERROR -1
#endif

#define NS_REQUEST_UNKNOWN     -1
#define NS_REQUEST_START 	0
#define NS_REQUEST_STOP 	1
#define NS_REQUEST_INFO 	2
#define NS_REQUEST_KILL 	3
#define NS_REQUEST_HELP 	4
#define NS_REQUEST_EXECUTE      5

#define NS_AUTOMOUNTS_DEV 	1
#define NS_AUTOMOUNTS_SYS       2
#define NS_AUTOMOUNTS_PROC 	4

#define NS_DEFAULT_CONFIG_PATH 		"/etc/nsjail/nsjail.conf"

#define NS_CONF_DEFINITIONS 	"jails"

#define NS_MAX_ID_LENGTH 	32
#define NS_MAX_CMD_LENGTH 	255
#define STACK_SIZE (1024 * 1024)

static char child_stack[STACK_SIZE];

typedef struct ns_user_opts {
	int request;
	char *selection;
	char *config_path;
	int daemonize;
} ns_user_opts_t;

typedef struct ns_network {
	const char *link;
	const char *interface;
	const char *address;
	const char *gateway;
} ns_network_t;

typedef struct ns_jail {
	const char *handle;
	const char *hostname;
	const char *domainname;
	char *init_cmd;
	char **init_args;
	char *uid_map;
	char *gid_map;
	char *root;
	int init_uid;
	int init_gid;
	int automounts;
	pid_t pid;
	ns_network_t *network;
} ns_jail_t;

typedef struct ns_conf {
	int verbosity;
	int signal_pipe[2];
	int jail_count;
	ns_jail_t *jails;
	config_t *fcfg;
	ns_user_opts_t *opts;
} ns_conf_t;

typedef struct ns_clone_args {
	ns_conf_t *config;
	ns_jail_t *jail;
} ns_clone_args_t;

typedef int (*ns_request_handler)(ns_user_opts_t *opts);
ns_user_opts_t *ns_parse_user_opts(int argc, char **argv);
ns_request_handler ns_dispatch_request(ns_user_opts_t *opts);
ns_conf_t *ns_init_config(ns_user_opts_t *opts);
int ns_load_config(ns_conf_t *config);
int ns_load_jail_config(config_setting_t *settings, ns_jail_t *jail);
int ns_free_config(ns_conf_t *config);

ns_jail_t *ns_lookup_jail(ns_conf_t *config, char *handle);
int ns_prepare_env(ns_conf_t *config, ns_jail_t *jail);
int ns_enter_env(ns_conf_t *config, ns_jail_t *jail);
int ns_cleanup(ns_conf_t *config, ns_jail_t *jail);

int ns_map_jail_ids(ns_jail_t *jail);
int ns_automount(ns_jail_t *jail);

int ns_setup_host_network(ns_conf_t *config, ns_jail_t *jail);
int ns_setup_jail_network(ns_conf_t *config, ns_jail_t *jail);

int ns_start_jail(ns_user_opts_t *opts);
int ns_stop_jail(ns_user_opts_t *opts);
int ns_jail_info(ns_user_opts_t *opts);
int ns_kill_jail(ns_user_opts_t *opts);
int ns_exec_jail(ns_user_opts_t *opts);
int ns_show_help(ns_user_opts_t *opts);

int ns_wait_signal(ns_conf_t *config);
int ns_send_signal(ns_conf_t *config);

static int ns_child(void *arg);

#endif // NSJAIL_H
