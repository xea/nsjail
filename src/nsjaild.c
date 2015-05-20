#include "nsjaild.h"

int main(int argc, char **argv) {

	int errsv = 0;

	if (daemon(0,0) == -1) {
		errsv = errno;
		(void) printf("Daemon error: %s\n", strerror(errsv));
	}

	return EXIT_SUCCESS;
}

