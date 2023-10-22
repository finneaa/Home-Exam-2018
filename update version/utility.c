#include "myshell.h"

int main() {
	init();
	int shouldrun = 1;
	/* Main function processing signal function */
	pact.sa_handler = sig_handler;
	/* Set the mask set */
	sigemptyset(&son_set);
	sigaddset(&son_set, SIGTSTP);
	sigaddset(&son_set, SIGINT);
	while (shouldrun) {
		/* Shielding signals such as ctrl+z and ctrl+c */
		sigprocmask(SIG_BLOCK, &son_set, NULL);
		signal(SIGINT, sig_handler);
		sigaction(SIGTSTP, &pact, NULL);
		/* Get the path shown in the shell */
		char* shell = get_display_line();
		fprintf(stdout, "%s", shell);
		fflush(stdout);
		free(shell);
		/* Read command */
		char** args = read_command();
		/* Excuting an order */
		execute(args);
		free(args);
	}
	return 0;
}
