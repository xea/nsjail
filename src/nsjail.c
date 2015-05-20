#include "nsjail.h"


/**
 * Initialises an empty nsjail_init_config object while there's no
 * proper configuration loading mechanism.
 *
 * This method always returns a newly allocated nsjail_conf_t struct.
 */
nsjail_conf_t * nsjail_default_config() {
	nsjail_conf_t * config = (nsjail_conf_t *) calloc(1, sizeof(nsjail_conf_t));
	int errsv = errno;

	if (config == NULL) {
		syslog(LOG_ERR, "Could not allocate memory for run-time configuration: %s\n", strerror(errsv));
		return NULL;
	}

	// TODO this should be replaced with a dynamic configuration but at this point it will suffice
	config->automount_count = 2;
	config->automounts = (nsjail_automount_entry_t *) calloc(config->automount_count, sizeof(nsjail_automount_entry_t));
	errsv = errno;

	if (config->automounts == NULL) {
		syslog(LOG_ERR, "Could not allocate memory for filesystem automounts: %s\n", strerror(errsv));
		return NULL;
	}

	config->automounts[0].type = "proc";
	config->automounts[0].source = "none";
	config->automounts[0].target = "/proc";
	config->automounts[0].options = MS_NOEXEC;

	config->automounts[1].type = "sysfs";
	config->automounts[1].source = "none";
	config->automounts[1].target = "/sys";
	config->automounts[1].options = MS_NOEXEC;

	// initialise the remaining variables

	config->container_root = NULL;
	config->hostname = NULL;
	config->exec_cmd = NULL;
	config->exec_argv = NULL;
	config->id_map = NULL;
	config->initial_uid = UID_ROOT;
	config->initial_gid = GID_ROOT;
	config->verbosity = 0;
	config->disable_namespaces = 0;
	config->disable_automounts = 0;

	return config;
}

/**
 * Frees dynamically allocated configuration objects
 */
void nsjail_destroy_config(nsjail_conf_t *config) {
	if (config != NULL) {
		free(config->automounts);
		free(config);
		syslog(LOG_DEBUG, "Run-time configuration has been freed");
	} else {
		syslog(LOG_WARNING, "Requested destroying of NULL configuration");
	}
}

/**
 * Attempts to parse command-line arguments and build an usable configuration
 * with reasonable defaults when arguments are missing.
 */
nsjail_conf_t * nsjail_parse_config(int argc, char **argv) {
	nsjail_conf_t *config = nsjail_default_config();

	if (config == NULL) {
		syslog(LOG_ERR, "Tried to parse NULL configuration");
		return NULL;
	}

	// used as a temporary storage of command line arguments
	int opt;

	while ((opt = getopt(argc, argv, "+NMvh:r:m:u:g:")) != -1) {
		switch (opt) {
		case 'r': config->container_root = optarg; break;
		case 'v': config->verbosity = 1; break;
		case 'h': config->hostname = optarg; break;
		case 'm': config->id_map = optarg; break;
			  // TODO use a better string conversion function than atoi
		case 'u': config->initial_uid = atoi(optarg); break;
		case 'g': config->initial_gid = atoi(optarg); break;
		case 'N': config->disable_namespaces = 1; break;
		case 'M': config->disable_automounts = 1; break;
		}
	}

	config->exec_cmd = argv[optind];
	config->exec_argv = &argv[optind];

	if (config->exec_cmd == NULL) {
		syslog(LOG_WARNING, "No executable argument was provided");
	}

	return config;
}

/**
 * Serves as an entry point for the newly cloned child process. 
 */
static int nsjail_child(void *arg) {
	nsjail_conf_t *config = (nsjail_conf_t *) arg;
	int errsv = 0;

	if (nsjail_wait_signal(config) == -1) {
		syslog(LOG_ERR, "Wait for child signal failed");
		return -1;
	}

	if (config->exec_cmd == NULL) {
		syslog(LOG_ERR, "No command was specified");
		return -1;
	}

	if (config->id_map != NULL) {
		if (setuid(config->initial_uid) == -1) {
			errsv = errno;
			syslog(LOG_ERR, "Couldn't set UID of child process: %s", strerror(errsv));
			return -1;
		}

		if (setgid(config->initial_gid) == -1) {
			errsv = errno;
			syslog(LOG_ERR, "Couldn't set GID of child process: %s", strerror(errsv));
			return -1;
		}
	}

	if (config->hostname != NULL) {
		struct utsname uts;

		if (sethostname(config->hostname, strlen(config->hostname)) == -1) {
			errsv = errno;
			syslog(LOG_ERR, "Couldn't set container hostname: %s", strerror(errsv));
			return -1;
		}

		if (uname(&uts) == -1) {
			errsv = errno;
			syslog(LOG_ERR, "Couldn't get container hostname: %s", strerror(errsv));
			return -1;
		}
		
		if (config->verbosity > 0) {
			printf("Child hostname: %s\n", uts.nodename);
		}
	}

	if (config->container_root == NULL) {
		syslog(LOG_INFO, "Container root directory is not specified");
	}

	if (!config->disable_automounts && nsjail_automount(config) == -1) {
		syslog(LOG_ERR, "Auto-mounting filesystems failed");
		return -1;
	}

	if (config->container_root != NULL && chroot(config->container_root) == -1) {
		syslog(LOG_ERR, "Couldn't chroot to container root");
		return -1;
	}

	nsjail_drop_capabilities();

	if (execvp(config->exec_cmd, config->exec_argv) == -1) {
		syslog(LOG_ERR, "Error during executing the program");
		return -1;
	}

	return 0;
}

int nsjail_map_ids(long pid, nsjail_conf_t *config) {
	char map_path[PATH_MAX];
	int fd;

	if (config == NULL || config->id_map == NULL) {
		syslog(LOG_ERR, "ID mapping configuration was not specified");
		return ERR_CONFIG_NOT_INITIALISED;
	}

	syslog(LOG_DEBUG, "Mapping ids");

	(void) snprintf(map_path, PATH_MAX, "/proc/%ld/uid_map", pid);
	fd = open(map_path, O_RDWR);

	if (fd == -1) {
		syslog(LOG_ERR, "Could not open UID map for writing");
		return -1;
	}

	write(fd, config->id_map, strlen(config->id_map));
	close(fd);

	(void) snprintf(map_path, PATH_MAX, "/proc/%ld/gid_map", pid);
	fd = open(map_path, O_RDWR);

	if (fd == -1) {
		syslog(LOG_ERR, "Could not open GID map for writing");
		return -1;
	}

	write(fd, config->id_map, strlen(config->id_map));
	close(fd);

	return 0;
}

/**
 * Waits on a config-provided pipe for a message (or more likely, for closing the pipe)
 */
int nsjail_wait_signal(nsjail_conf_t *config) {
	if (config == NULL) {
		return ERR_CONFIG_NOT_INITIALISED;
	}

	char ch;

	syslog(LOG_DEBUG, "Waiting for signal");

	close(config->pipe_fd[1]);

	if (read(config->pipe_fd[0], &ch, 1) != 0) {
		syslog(LOG_ERR, "Error during waiting for pipe");
		return -1;
	}

	return 0;
}

/**
 * Sends a signal to the waiting process signalling that it shouldn't wait anymore
 */
int nsjail_send_signal(nsjail_conf_t *config) {
	if (config == NULL) {
		syslog(LOG_ERR, "Invalid configuration");
		return ERR_CONFIG_NOT_INITIALISED;
	}

	syslog(LOG_DEBUG, "Sending signal");

	if (close(config->pipe_fd[1]) == -1) {
		return -1;
	}

	return 0;
}

/**
 * Prepares the jailed process by setting it's namespaces, UID's, etc.
 */
int nsjail_enter_environment(nsjail_conf_t *config) {
	int flags = SIGCHLD;

	if (!config->disable_namespaces) {
		flags = flags | CLONE_NEWPID | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWNS | CLONE_NEWNET | CLONE_NEWUSER;
	}

	if (pipe(config->pipe_fd) == -1) {
		syslog(LOG_ERR, "Error creating pipe");
		return -1;
	}

	config->child_pid = clone(nsjail_child, child_stack + STACK_SIZE, flags, (void *) config);

	if (config->child_pid == -1) {
		syslog(LOG_ERR, "Could not clone process, aborting");
		return -1;
	}


	if (config->id_map != NULL && nsjail_map_ids((long) config->child_pid, config) == -1) {
		syslog(LOG_ERR, "Error mapping UID/GIDs");
		return -1;
	}

	nsjail_send_signal(config);

	nsjail_lose_dignity();

	if (waitpid(config->child_pid, NULL, 0) == -1) {
		syslog(LOG_ERR, "Error while waiting for child");
		return -1;
	}

	return 0;
}

int nsjail_automount(nsjail_conf_t *config) {
	if (config != NULL) {
		for (int i = 0; i < config->automount_count; i++) {
			nsjail_automount_entry_t *mp = &config->automounts[i];

			// 4096 character long maximum allowed path seems reasonably long
			// TODO here should be a calculated path length anyway
			char *relative_mp = (char *) calloc(4096, sizeof(char));
			if (snprintf(relative_mp, 4096, "%s%s", config->container_root, mp->target) == -1) {
				syslog(LOG_ERR, "Couldn't generate automount path");
			} else {
				if (config->verbosity > 0) {
					printf("Mounting type %s %s to %s\n", mp->type, mp->source, relative_mp);
				}

				if (mount(mp->source, relative_mp, mp->type, mp->options, (void *) NULL) == -1) {
					syslog(LOG_ERR, "Mount fail");
				}
			}
		}
	}

	return 0;
}

/**
 * Disables as many of the root capabilities this process possesses as possible.
 *
 * Currently, this is done by switching UID and GID to a safe (overflow) GID/UID
 */
void nsjail_lose_dignity() {
	if (setgid(DEFAULT_OVERFLOWGID) == -1) {
		syslog(LOG_ERR, "Couldn't set safe parent GID");
	}

	if (setuid(DEFAULT_OVERFLOWUID) == -1) {
		syslog(LOG_ERR, "Couldn't set safe parent UID");
	}
}

int nsjail_drop_capabilities() {
	return 0;
}

void print_capabilities(pid_t pid) {
	printf("eUID: %ld; eGID: %ld; UID: %ld, GID: %ld, capabilities: %s\n", (long) geteuid(), (long)getegid(), (long) getuid(), (long) getgid(), cap_to_text(cap_get_pid(pid), NULL));
}

int main(int argc, char **argv) {
	openlog(NULL, LOG_PID, LOG_USER);

	syslog(LOG_DEBUG, "NSJail starting up");

	nsjail_conf_t *config = nsjail_parse_config(argc, argv); 

	if (config->exec_cmd == ERR_NO_EXECUTABLE) {
		syslog(LOG_ERR, "No executable was specified");
		return EXIT_FAILURE;
	}

	if (nsjail_enter_environment(config) == ERR_ENVIRONMENT_FAILED) {
		syslog(LOG_ERR, "Failed to enter chrooted environment");
		return EXIT_FAILURE;
	}

	nsjail_destroy_config(config);

	closelog();

	return EXIT_SUCCESS;
}
