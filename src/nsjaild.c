#include "nsjaild.h"

int nsjaild_daemonize();

int nsjaild_daemonize() {
	int errsv = 0;

	if (daemon(0,0) == -1) {
		errsv = errno;
		syslog(LOG_ERR, "Daemon error: %s\n", strerror(errsv));
		return -1;
	}
	
	return 0;
}


int main(int argc, char **argv) {
	
	openlog(NULL, LOG_PID | LOG_PERROR, LOG_USER);

	int len, st;
	
	st = socket(AF_UNIX, SOCK_STREAM, 0);

	closelog();

	return EXIT_SUCCESS;
}

