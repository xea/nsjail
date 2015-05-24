#include "nsjail.h"

/**
 * Parse command-line arguments (or arguments from ny other source) and restructures them
 * into an ns_user_opts_t.
 *
 * This function returns NULL on error or a pointer to an initialized ns_user_opts_t if
 * it was successful.
 */
ns_user_opts_t *ns_parse_user_opts(int argc, char **argv) {
	ns_user_opts_t *useropts = (ns_user_opts_t *) calloc(1, sizeof(ns_user_opts_t));

	if (useropts == NULL) {
		syslog(LOG_ERR, "Could not allocate memory for user options: %s", strerror(errno));
		return NULL;
	}

	// step 1: initialise default vaules
	useropts->request = NS_REQUEST_UNKNOWN;
	useropts->config_path = NULL;
	useropts->selection = NULL;

	// step 2: read command-line switches
	int opt;
	int parse_error = FALSE;

	while ((opt = getopt(argc, argv, "+ehf:")) != -1) {
		switch (opt) {
		case 'f': useropts->config_path = optarg; 	break;
		case 'h': useropts->request = NS_REQUEST_HELP;  break;
		case 'e': 
			useropts->request = NS_REQUEST_EXECUTE; 
			useropts->selection = optarg; 	
			break;
		default: parse_error = TRUE; 			break;
		}

		if (parse_error == TRUE) {
			useropts->request = NS_REQUEST_HELP;
			break;
		}
	}

	// step 3: check additional arguments
	if (!parse_error && argc > optind) {
		if (useropts->request == NS_REQUEST_EXECUTE) {
		} else if (strcmp("start", argv[optind]) == 0) {
			useropts->request = NS_REQUEST_START;
		} else if (strcmp("stop", argv[optind]) == 0) {
			useropts->request = NS_REQUEST_STOP;
		} else if (strcmp("kill", argv[optind]) == 0) {
			useropts->request = NS_REQUEST_KILL;
		} else if (strcmp("info", argv[optind]) == 0) {
			useropts->request = NS_REQUEST_INFO;
		}

		if (argc > optind + 1) {
			useropts->selection = argv[optind + 1];
		}
	}

	return useropts;
}

/**
 * Decides which action to perform based on user-supplied options and returns the appropriate
 * handler function or NULL if there was an unrecoverable error.
 */
ns_request_handler ns_dispatch_request(ns_user_opts_t *opts) {
	if (opts == NULL) {
		syslog(LOG_ERR, "Couldn't dispatch NULL request");
		return NULL;
	} else {
		int (* handler)(ns_user_opts_t *) = NULL;

		switch (opts->request) {
		case NS_REQUEST_START:
			handler = &ns_start_jail;
			break;
		case NS_REQUEST_STOP:
			handler = &ns_stop_jail;
			break;
		case NS_REQUEST_INFO:
			break;
		case NS_REQUEST_KILL:
			break;
		case NS_REQUEST_EXECUTE:
			handler = &ns_exec_jail;
			break;
		case NS_REQUEST_UNKNOWN:
		case NS_REQUEST_HELP:
		default:
			handler = &ns_show_help;
			break;
		}

		return handler;
	}
}

/**
 * Allocate and initialize a chunk of memory for the run-time configuration
 */
ns_conf_t *ns_init_config(ns_user_opts_t *opts) {
	ns_conf_t *config = (ns_conf_t *) calloc(1, sizeof(ns_conf_t));

	if (config == NULL) {
		syslog(LOG_ERR, "Couldn't allocate memory for run-time configuration: %s\n", strerror(errno));
	} else {
		config->verbosity = 0;
		config->opts = opts;
		config->jail_count = 0;
		config->jails = NULL;
		config->fcfg = NULL;
	}

	return config;
}

/**
 * Load run-time configuration from the location specified in config->opts->config_path.
 */
int ns_load_config(ns_conf_t *config) {
	if (config == NULL) {
		syslog(LOG_ERR, "Couldn't load config to NULL");
		return -1;
	}

	config->fcfg = (config_t *) calloc(1, sizeof(config_t));

	if (config->fcfg == NULL) {
		syslog(LOG_ERR, "Couldn't allocate memory for run-time configuration: %s", strerror(errno));
		return -1;
	}

	// Initialize and test libconfig
	config_init(config->fcfg);

	if (!config_read_file(config->fcfg, config->opts->config_path)) {
		syslog(LOG_ERR, "Couldn't load configuration file: %s\n%s:%d - %s\n", config->opts->config_path,
			config_error_file(config->fcfg), config_error_line(config->fcfg), config_error_text(config->fcfg));
		config_destroy(config->fcfg);
		return -1;
	}

	config_setting_t *setting = config_lookup(config->fcfg, NS_CONF_DEFINITIONS);

	if (setting != NULL) {
		config->jail_count = config_setting_length(setting);	

		int i = 0;

		ns_jail_t *jails = (ns_jail_t *) calloc(config->jail_count, sizeof(ns_jail_t));

		// Load per-jail configuration
		for (i = 0; i < config->jail_count; i++) {
			config_setting_t *definition = config_setting_get_elem(setting, i);

			if (ns_load_jail_config(definition, &jails[i]) == -1) {
				syslog(LOG_WARNING, "Error while loading jail configuration: %s", definition->name);
			}
		}

		syslog(LOG_INFO, "Loaded %d jail configurations", config->jail_count);
		config->jails = jails;
	} else {
		syslog(LOG_WARNING, "Could not find jail definitions");
	}

	syslog(LOG_INFO, "Configuration loaded");

	return 0;
}

/**
 * Load per-jail configuration. If a configuration setting is not available then it defaults that setting
 * to NULL or 0.
 */
int ns_load_jail_config(config_setting_t *settings, ns_jail_t *jail) {
	jail->handle = settings->name;
	config_setting_lookup_string(settings, "hostname", &jail->hostname);
	config_setting_lookup_string(settings, "domainname", &jail->domainname);
	config_setting_lookup_string(settings, "init_cmd", (const char **) &jail->init_cmd);

	config_setting_t *args = (config_setting_get_member(settings, "init_args"));

	if (args != NULL && config_setting_is_array(args)) {
		int argc = config_setting_length(args);

		if (argc > 0) {
			jail->init_args = (char **) calloc(argc, sizeof(char *));

			int argci = 0;

			for (argci = 0; argci < argc; argci++) {
				jail->init_args[argci] = (char *)config_setting_get_string_elem(args, argci);
			}
		}
	}
	
	config_setting_lookup_string(settings, "root", (const char **) &jail->root);
	config_setting_lookup_string(settings, "uid_map", (const char **) &jail->uid_map);
	config_setting_lookup_string(settings, "gid_map", (const char **) &jail->gid_map);

	if (config_setting_lookup_int(settings, "init_uid", &jail->init_uid) == CONFIG_FALSE) {
		jail->init_uid = -1;
	}

	if (config_setting_lookup_int(settings, "init_gid", &jail->init_gid) == CONFIG_FALSE) {
		jail->init_gid = -1;
	}

	config_setting_t *automounts = (config_setting_get_member(settings, "automounts"));

	if (automounts != NULL && config_setting_is_array(args)) {
		int c = config_setting_length(automounts);

		if (c > 0) {
			int ci = 0;

			for (ci = 0; ci < c; ci++) {
				if (strncmp("dev", config_setting_get_string_elem(automounts, ci), 3) == 0) {
					jail->automounts |= NS_AUTOMOUNTS_DEV;
				} else if (strncmp("sys", config_setting_get_string_elem(automounts, ci), 3) == 0) {
					jail->automounts |= NS_AUTOMOUNTS_SYS;
				} else if (strncmp("proc", config_setting_get_string_elem(automounts, ci), 4) == 0) {
					jail->automounts |= NS_AUTOMOUNTS_PROC;
				}
			}
		}
	}

	return 0;
}

int ns_free_config(ns_conf_t *config) {
	if (config != NULL) {
		if (config->fcfg != NULL) {
			config_destroy(config->fcfg);
			free(config->fcfg);
		}

		if (config->jails != NULL) {
			int i = 0;

			for (i = 0; i < config->jail_count; i++) {
				free(config->jails[i].init_args);
			}

			free(config->jails);
		}

		free(config);
	}

	return 0;
}

/**
 * Retreives a jail configuration that matches the given handle or NULL if no matching jail configurations 
 * were found.
 */
ns_jail_t *ns_lookup_jail(ns_conf_t *config, char *handle) {
	ns_jail_t *jail = NULL;


	if (config != NULL && handle != NULL) {
		int i = 0;

		for (i = 0; i < config->jail_count; i++) {
			if (strcmp(handle, config->jails[i].handle) == 0) {
				jail = &config->jails[i];
				break;
			}
		}

		if (jail == NULL) {
			syslog(LOG_WARNING, "Couldn't look up jail: %s", handle);
		}
	}

	return jail;
}

int ns_prepare_env(ns_conf_t *config, ns_jail_t *jail) {
	int flags = SIGCHLD | CLONE_NEWPID | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWNS | CLONE_NEWNET | CLONE_NEWUSER;	

	if (pipe(config->signal_pipe) == -1) {
		syslog(LOG_ERR, "Couldn't create signal pipe: %s", strerror(errno));
		return -1;
	}

	ns_clone_args_t args;
	args.config = config;
	args.jail = jail;

	jail->pid = clone(ns_child, child_stack + STACK_SIZE, flags, (void *) &args);

	if (ns_map_jail_ids(jail) == -1) {
		syslog(LOG_ERR, "Couldn't map ids :<");
	}

	if (ns_send_signal(config) == -1) {
		syslog(LOG_ERR, "Couldn't send signal: %s\n", strerror(errno));
		return -1;
	}

	if (jail->pid == -1) {
		syslog(LOG_ERR, "Couldn't clone() process: %s", strerror(errno));
		return -1;
	}

	return 0;
}

int ns_enter_env(ns_conf_t *config, ns_jail_t *jail) {
	(void) config;
	(void) jail;

	if (ns_prepare_env(config, jail) == NS_ERROR) {
		syslog(LOG_ERR, "Couldn't prepare jail environment");
		return -1;
	}

	if (waitpid(jail->pid, NULL, 0) == -1) {
		syslog(LOG_ERR, "Error while waiting for child");
		return -1;
	}
	


	return 0;
}

int ns_map_jail_ids(ns_jail_t *jail) {
	char map_path[PATH_MAX];
	int fd;

	if (jail == NULL) {
		syslog(LOG_ERR, "Couldn't map jail id's: a jail was not specified");
		return -1;
	}

	syslog(LOG_DEBUG, "Mapping ids");

	if (jail->uid_map != NULL) {
		(void) snprintf(map_path, PATH_MAX, "/proc/%d/uid_map", jail->pid);
		fd = open(map_path, O_RDWR);

		if (fd == -1) {
			syslog(LOG_ERR, "Could not open UID map for writing");
			return -1;
		}

		if (write(fd, jail->uid_map, strlen(jail->uid_map)) == -1) {
			syslog(LOG_ERR, "Error during mapping UID: %s", strerror(errno));
		} else {
			syslog(LOG_INFO, "Mapped UID: %s", jail->uid_map);
		}

		close(fd);
	} else {
		syslog(LOG_INFO, "No UID mapping was found");
	}

	if (jail->gid_map != NULL) {
		(void) snprintf(map_path, PATH_MAX, "/proc/%d/gid_map", jail->pid);
		fd = open(map_path, O_RDWR);

		if (fd == -1) {
			syslog(LOG_ERR, "Could not open GID map for writing");
			return -1;
		}

		if (write(fd, jail->gid_map, strlen(jail->gid_map)) == -1) {
			syslog(LOG_ERR, "Error during mapping GID: %s", strerror(errno));
		} else {
			syslog(LOG_INFO, "Mapped GID: %s", jail->gid_map);
		}

		close(fd);
	} else {
		syslog(LOG_INFO, "No GID mapping was found");
	}

	return 0;
}

int ns_wait_signal(ns_conf_t *config) {
	if (config == NULL) {
		return -1;
	}

	char ch;

	syslog(LOG_DEBUG, "Waiting for signal");

	close(config->signal_pipe[1]);

	if (read(config->signal_pipe[0], &ch, 1) != 0) {
		syslog(LOG_ERR, "Error during waiting for pipe");
		return -1;
	}

	syslog(LOG_DEBUG, "Received signal");

	return 0;
}

int ns_send_signal(ns_conf_t *config) {
	if (config == NULL) {
		syslog(LOG_ERR, "Invalid configuration");
		return -1;
	}

	syslog(LOG_DEBUG, "Sending signal");

	if (close(config->signal_pipe[1]) == -1) {
		return -1;
	}

	return 0;
}


static int ns_child(void *args) {
	ns_clone_args_t *clone_args = (ns_clone_args_t *) args;
	ns_conf_t *config = clone_args->config;
	ns_jail_t *jail = clone_args->jail;

	if (ns_wait_signal(config) == -1) {
		syslog(LOG_ERR, "Error during waiting for signal: %s", strerror(errno));
		return -1;
	}

	if (jail->init_uid > -1 && setuid(jail->init_uid) == -1) {
		syslog(LOG_ERR, "Couldn't set child UID to %d: %s", jail->init_uid, strerror(errno));
		return -1;
	}
	
	if (jail->init_gid > -1 && setgid(jail->init_gid) == -1) {
		syslog(LOG_ERR, "Couldn't set child GID to %d: %s", jail->init_gid, strerror(errno));
		return -1;
	}

	if (jail->hostname != NULL) {
		struct utsname uts;

		if (sethostname(jail->hostname, strlen(jail->hostname)) == -1) { 
			syslog(LOG_ERR, "Couldn't set child hostname to %s: %s", jail->hostname, strerror(errno));
			return -1;
		}

		if (uname(&uts) == -1) {
			syslog(LOG_WARNING, "Couldn't verify child hostname: %s", strerror(errno));
		} else {
			syslog(LOG_INFO, "Child hostname is set to: %s", jail->hostname);
		}
	}

	if (jail->domainname != NULL) {
		if (setdomainname(jail->domainname, strlen(jail->domainname)) == -1) {
			syslog(LOG_ERR, "Couldn't set child domainname to %s: %s", jail->domainname, strerror(errno));
			return -1;
		}
	}

	if (jail->root != NULL) {
		if (chroot(jail->root) == -1) {
			syslog(LOG_ERR, "Couldn't chroot() to %s: %s", jail->root, strerror(errno));
			return -1;
		}
		syslog(LOG_INFO, "Chroot()'d to %s", jail->root);
	}

	if (jail->automounts > 0) {
		if (ns_automount(jail) == -1) {
			syslog(LOG_ERR, "Couldn't automount jail fs");
			return -1;
		}
	}


	if (execvp(jail->init_cmd, jail->init_args) == -1) {
		syslog(LOG_ERR, "Error during executing the program: %s", strerror(errno));
		return -1;
	}
	return 0;
}

int ns_automount(ns_jail_t *jail) {
	if (jail == NULL) {
		return -1;
	}

	if (jail->automounts && NS_AUTOMOUNTS_PROC) {
		if (mount("none", "/proc", "proc", MS_NOEXEC, (void *)NULL) == -1) {
			syslog(LOG_ERR, "Could not mount procfs: %s", strerror(errno));
			return -1;
		}
	}
	if (jail->automounts && NS_AUTOMOUNTS_SYS) {
		if (mount("none", "/sys", "sysfs", MS_NOEXEC, (void *)NULL) == -1) {
			syslog(LOG_ERR, "Could not mount ssyfs: %s", strerror(errno));
			return -1;
		}
	}

	return 0;
}

int ns_start_jail(ns_user_opts_t *opts) {
	syslog(LOG_INFO, "Starting jail");

	if (opts->selection == NULL) {
		syslog(LOG_ERR, "Didn't specify jail");
		return -1;
	}

	ns_conf_t *config = ns_init_config(opts);

	if (ns_load_config(config) == NS_ERROR) {
		syslog(LOG_ERR, "Couldn't load configuration");
		return -1;
	}

	ns_jail_t *jail = ns_lookup_jail(config, config->opts->selection);

	if (jail == NULL) {
		syslog(LOG_ERR, "Couldn't find jail: %s\n", config->opts->selection);
		return -1;
	}

	if (ns_enter_env(config, jail) == NS_ERROR) {
		syslog(LOG_ERR, "Couldn't enter jail environment");
		return -1;
	}

	ns_free_config(config);

	syslog(LOG_INFO, "Jail started");
	return 0;
}

int ns_stop_jail(ns_user_opts_t *opts) {
	(void) opts;
	printf("Not implemented yet :<\n");
	return 0;
}

int ns_info_jail(ns_user_opts_t *opts) {
	(void) opts;
	printf("Not implemented yet :<\n");
	return 0;
}

int ns_kill_jail(ns_user_opts_t *opts) {
	(void) opts;
	printf("Not implemented yet :<\n");
	return 0;
}

int ns_exec_jail(ns_user_opts_t *opts) {
	(void) opts;
	printf("Not implemented yet :<\n");
	return 0;
}

/**
 * Display help message about program usage
 */
int ns_show_help(ns_user_opts_t *opts) {
	(void) opts;
	printf("Usage: nsjail [opts] <action> [jail]\n");
	printf("  Available opts are the following:\n");
	printf("      -f <config>       Load configuration from <config> instead of %s\n", NS_DEFAULT_CONFIG_PATH);
	printf("\n  Available actions are the following:\n");
	printf("      start             Start a jail\n");
	printf("      stop              Stop a jail\n");
	printf("      info              Display run-time information about a jail\n");
	printf("      kill              Forcefully terminate a jail\n");
	printf("      exec              Execute a command within a jail\n");
	return 0;
}

int main(int argc, char **argv) {
	openlog(NULL, LOG_PID | LOG_PERROR, LOG_USER);

	ns_user_opts_t *opts = ns_parse_user_opts(argc, argv);

	printf("Reality check: request: %d jail: %s\n", opts->request, opts->selection);

	ns_request_handler handler = ns_dispatch_request(opts);

	if (handler != NULL) {
		int status = (*handler)(opts);

		if (status == NS_ERROR) {
			syslog(LOG_ERR, "Error during execution :<");
		}
	} else {
		syslog(LOG_ERR, "Couldn't find handler for request");
	}

	closelog();

	return 0;
}

