#include "nsjail.h"


/**
 * Initialises an empty nsjail_init_config object while there's no
 * proper configuration loading mechanism.
 *
 * This method always returns a newly allocated nsjail_conf_t struct.
 */
nsjail_conf_t * nsjail_default_config() {
	DEBUG("Initialising NSJail configuration");

	/*char * config_data[][4] = {
		{ "proc", "none", "/proc", NULL },
		{ "sysfs", "none", "/sys", NULL }
	};*/

	nsjail_conf_t * config = (nsjail_conf_t *) calloc(1, sizeof(nsjail_conf_t));

	// TODO this value should not be set to a fix number, this is just for testing purposes
	if (config == NULL) {
		ERROR("Initialising configuration has failed");
		return NULL;
	}

	config->automount_count = 2;
	config->automounts = (nsjail_automount_entry_t *) calloc(config->automount_count, sizeof(nsjail_automount_entry_t));

	if (config->automounts == NULL) {
		ERROR("Allocating memory for the configuration has failed");
		return NULL;
	}

	config->automounts[0].type = "proc";
	config->automounts[0].source = "none";
	config->automounts[0].target = "/proc";
	config->automounts[0].options = NULL;

	config->automounts[1].type = "sysfs";
	config->automounts[1].source = "none";
	config->automounts[1].target = "/sys";
	config->automounts[1].options = NULL;

	// initialise the remaining variables

	config->container_root = DEFAULT_CONTAINER_ROOT;
	config->hostname = NULL;
	config->exec_cmd = NULL;
	config->exec_argv = NULL;
	config->id_map = NULL;
	config->verbosity = 0;

	return config;
}

/**
 * Frees dynamically allocated configuration objects
 */
void nsjail_destroy_config(nsjail_conf_t *config) {
	if (config != NULL) {
		free(config->automounts);
		free(config);
	}
}

/**
 * Attempts to parse command-line arguments and build an usable configuration
 * with reasonable defaults when arguments are missing.
 */
nsjail_conf_t * nsjail_parse_config(int argc, char **argv) {
	nsjail_conf_t *config = nsjail_default_config();


	// used as a temporary storage of command line arguments
	int opt;

	while ((opt = getopt(argc, argv, "+vh:r:m:")) != -1) {
		switch (opt) {
		case 'r': config->container_root = optarg; break;
		case 'v': config->verbosity = 1; break;
		case 'h': config->hostname = optarg; break;
		case 'm': config->id_map = optarg; break;
		}
	}

	config->exec_cmd = argv[optind];
	config->exec_argv = &argv[optind];

	return config;
}

/**
 * Serves as an entry point for the newly cloned child process. 
 */
static int nsjail_child(void *arg) {
	nsjail_conf_t *config = (nsjail_conf_t *) arg;

	if (nsjail_wait_signal(config) == -1) {
		ERROR("Wait for child signal failed");
		return -1;
	}

	if (config->exec_cmd == NULL) {
		ERROR("No command was specified");
		return -1;
	}

	if (setuid(UID_ROOT) == -1) {
		ERROR("SetUID fail");
		return -1;
	}

	if (setgid(GID_ROOT) == -1) {
		ERROR("SetGID fail");
		return -1;
	}

	if (config->hostname != NULL) {
		struct utsname uts;

		if (sethostname(config->hostname, strlen(config->hostname)) == -1) {
			ERROR("Error during setting hostname");
			return -1;
		}

		if (uname(&uts) == -1) {
			ERROR("Error during getting hostname");
			return -1;
		}
		
		if (config->verbosity > 0) {
			printf("Child hostname: %s\n", uts.nodename);
		}
	}


	if (execvp(config->exec_cmd, config->exec_argv) == -1) {
		ERROR("Error during executing the program");
		return -1;
	}

	return 0;
}

int nsjail_map_ids(long pid, nsjail_conf_t *config) {
	char map_path[PATH_MAX];
	int fd;

	if (config == NULL || config->id_map == NULL) {
		ERROR("ID mapping configuration was not specified");
		return ERR_CONFIG_NOT_INITIALISED;
	}

	DEBUG("Mapping ids");

	(void) snprintf(map_path, PATH_MAX, "/proc/%ld/uid_map", pid);
	fd = open(map_path, O_RDWR);

	if (fd == -1) {
		ERROR("Could not open UID map for writing");
		return -1;
	}

	write(fd, config->id_map, strlen(config->id_map));
	close(fd);

	DEBUG("UID mapped");

	(void) snprintf(map_path, PATH_MAX, "/proc/%ld/gid_map", pid);
	fd = open(map_path, O_RDWR);

	if (fd == -1) {
		ERROR("Could not open GID map for writing");
		return -1;
	}

	write(fd, config->id_map, strlen(config->id_map));
	close(fd);

	DEBUG("GID mapped");

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

	DEBUG("Waiting for signal");

	close(config->pipe_fd[1]);

	if (read(config->pipe_fd[0], &ch, 1) != 0) {
		ERROR("Error during waiting for pipe");
		return -1;
	}

	return 0;
}

/**
 * Sends a signal to the waiting process signalling that it shouldn't wait anymore
 */
int nsjail_send_signal(nsjail_conf_t *config) {
	if (config == NULL) {
		ERROR("Invalid configuration");
		return ERR_CONFIG_NOT_INITIALISED;
	}

	DEBUG("Sending signal");
	if (close(config->pipe_fd[1]) == -1) {
		return -1;
	}

	return 0;
}

/**
 * Prepares the jailed process by setting it's namespaces, UID's, etc.
 */
int nsjail_enter_environment(nsjail_conf_t *config) {
	int flags = CLONE_NEWPID | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWNS | CLONE_NEWNET | CLONE_NEWUSER | SIGCHLD;

	if (pipe(config->pipe_fd) == -1) {
		ERROR("Error creating pipe");
		return -1;
	}

	config->child_pid = clone(nsjail_child, child_stack + STACK_SIZE, flags, (void *) config);

	if (config->child_pid == -1) {
		ERROR("Could not clone process, aborting");
		return -1;
	}

	if (nsjail_map_ids((long) config->child_pid, config) == -1) {
		ERROR("Error mapping UID/GIDs");
		return -1;
	}

	nsjail_send_signal(config);

	if (waitpid(config->child_pid, NULL, 0) == -1) {
		ERROR("Error while waiting for child");
		return -1;
	}

	return 0;
}

int nsjail_automount(nsjail_conf_t *config) {
	if (config != NULL) {
		for (int i = 0; i < config->automount_count; i++) {
			if (config->verbosity > 0) {
				printf("Mounting %s\n", config->automounts[i].target);
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
	if (setuid(DEFAULT_OVERFLOWUID) == -1) {
		ERROR("Couldn't set safe parent UID");
	}
	
	if (setgid(DEFAULT_OVERFLOWGID) == -1) {
		ERROR("Couldn't set safe parent GID");
	}
}

int main(int argc, char **argv) {
	nsjail_conf_t *config = nsjail_parse_config(argc, argv); 

	if (config->exec_cmd == ERR_NO_EXECUTABLE) {
		ERROR("No executable was specified");
		return EXIT_FAILURE;
	}

	if (nsjail_automount(config) == ERR_AUTOMOUNT_FAILED) {
		ERROR("Failed to automount filesystems");
		return EXIT_FAILURE;
	}

	if (nsjail_enter_environment(config) == ERR_ENVIRONMENT_FAILED) {
		ERROR("Failed to enter chrooted environment");
		return EXIT_FAILURE;
	}

	nsjail_lose_dignity();
	nsjail_destroy_config(config);

	return EXIT_SUCCESS;
}
