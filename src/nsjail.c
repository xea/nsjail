#include "nsjail.h"


/**
 * Initialises an empty nsjail_init_config object while there's no
 * proper configuration loading mechanism.
 */
nsjail_conf_t * nsjail_default_config() {
	DEBUG("Initialising NSJail configuration");

	/*char * config_data[][4] = {
		{ "proc", "none", "/proc", NULL },
		{ "sysfs", "none", "/sys", NULL }
	};*/

	nsjail_conf_t * config = (nsjail_conf_t *) calloc(1, sizeof(nsjail_conf_t));

	config->automount_count = 2;
	config->automounts = (nsjail_automount_entry_t *) calloc(config->automount_count, sizeof(nsjail_automount_entry_t));

	config->automounts[0].type = "proc";
	config->automounts[0].source = "none";
	config->automounts[0].target = "/proc";
	config->automounts[0].options = NULL;

	config->automounts[1].type = "sysfs";
	config->automounts[1].source = "none";
	config->automounts[1].target = "/sys";
	config->automounts[1].options = NULL;

	config->container_root = DEFAULT_CONTAINER_ROOT;
	config->hostname = NULL;
	config->exec_cmd = NULL;
	config->exec_argv = NULL;
	config->verbosity = 0;

	return config;
}

/**
 * Attempts to parse command-line arguments and build an usable configuration
 * with reasonable defaults when arguments are missing.
 */
nsjail_conf_t * nsjail_parse_config(int argc, char **argv) {
	nsjail_conf_t *config = nsjail_default_config();

	int opt;

	while ((opt = getopt(argc, argv, "+vh:r:")) != -1) {
		switch (opt) {
		case 'r': config->container_root = optarg; break;
		case 'v': config->verbosity = 1; break;
		case 'h': config->hostname = optarg; break;
		}
	}

	config->exec_cmd = argv[optind];
	config->exec_argv = &argv[optind];

	return config;
}

static int nsjail_child(void *arg) {
	nsjail_conf_t *config = (nsjail_conf_t *) arg;

	if (nsjail_wait_signal(config) == -1) {
		return -1;
	}

	if (config->exec_cmd == NULL) {
		ERROR("No command was specified");
		return -1;
	}

	if (setuid(0) == -1) {
		ERROR("SetUID fail");
	}

	if (setgid(0) == -1) {
		ERROR("SetGID fail");
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


	// exec command
	execvp(config->exec_cmd, config->exec_argv);
	//system(config->exec_cmd);

	return 0;
}

int nsjail_map_ids(long pid) {
	char map_path[PATH_MAX];
	char *mapping = "0 120000 10000";
	int fd;

	DEBUG("Mapping ids");

	snprintf(map_path, PATH_MAX, "/proc/%ld/uid_map", pid);
	fd = open(map_path, O_RDWR);
	write(fd, mapping, strlen(mapping));
	close(fd);

	DEBUG("UID mapped");

	snprintf(map_path, PATH_MAX, "/proc/%ld/gid_map", pid);
	fd = open(map_path, O_RDWR);
	write(fd, mapping, strlen(mapping));
	close(fd);

	DEBUG("GID mapped");

	return 0;
}

int nsjail_wait_signal(nsjail_conf_t *config) {
	char ch;

	DEBUG("Waiting for signal");

	close(config->pipe_fd[1]);

	if (read(config->pipe_fd[0], &ch, 1) != 0) {
		ERROR("Error during waiting for pipe");
		return -1;
	}

	return 0;
}

int nsjail_send_signal(nsjail_conf_t *config) {
	DEBUG("Sending signal");
	close(config->pipe_fd[1]);
	return 0;
}

void nsjail_enter_environment(nsjail_conf_t *config) {
	int flags = CLONE_NEWPID | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWNS | CLONE_NEWNET | CLONE_NEWUSER | SIGCHLD;

	if (pipe(config->pipe_fd) == -1) {
		ERROR("Error creating pipe");
	}

	config->child_pid = clone(nsjail_child, child_stack + STACK_SIZE, flags, (void *) config);

	if (nsjail_map_ids((long) config->child_pid) == -1) {
		ERROR("Error mapping UID/GIDs");
	}

	nsjail_send_signal(config);

	if (waitpid(config->child_pid, NULL, 0) == -1) {
		ERROR("Error while waiting for child");
	}


}

/**
 * Frees dynamically allocated configuration objects
 */
void nsjail_destroy_config(nsjail_conf_t *config) {
	free(config->automounts);
	free(config);
}

void nsjail_automount(nsjail_conf_t *config) {
	if (config != NULL) {
		for (int i = 0; i < config->automount_count; i++) {
			if (config->verbosity > 0) {
				printf("Mounting %s\n", config->automounts[i].target);
			}
		}
	}
}

int main(int argc, char **argv) {
	nsjail_conf_t *config = nsjail_parse_config(argc, argv); 

	if (config->exec_cmd == NULL) {
		ERROR("No executable was specified");
		return -1;
	}

	nsjail_automount(config);

	nsjail_enter_environment(config);

	nsjail_destroy_config(config);

	return EXIT_SUCCESS;
}
