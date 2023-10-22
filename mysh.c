//start

#include "myshell.h"

char* internal_cmd[] = {"jobs", "kill", "quit", "history", NULL};

char buffer[MAXLINE];	 // midlertidig rekkefølge
char cmdline[MAXLINE];	// les kommando, kommando for å lagre array
char pathname[MAXSIZE];	// sti tilleggsarray
char processname[MAXSIZE];	// path hjelpe-array
char* variable[MAXLINE];	// vanlig variabel streng array
char* environ[MAXLINE];		// miljøvariabel streng array
char* history[MAXSIZE];		// history command string array
static int history_num = 0;	// antall historikkkommandoer
static int environ_num = 0;	// antall miljøvariabler
static int variable_num = 0;	// antall ordinære variabler
static int para_count = 0;	// Antallet argumenter som sendes til det nåværende skriptet
static int is_back = 0;		// om det kjører i bakgrunnen
static int run_flag = 1;	// om å fortsette å kjøre
pid_t son_pid = 0;			// prosessnummer til barnprosessen
struct winsize size;		// skjermstørrelse
typedef struct job {		// Kjør kommandolinjen i bakgrunnen
	pid_t pid;
	char state[8];
	char cmd[20];
	struct job *next;
}job;
job *head, *tail;     // hode, hale

/* Søk etter et rent minne (alle byte er '\ 0') */
char* malloc_clear(int len) {
	char* ret = (char*)malloc(len);
	memset(ret, '\0', len);
	return ret;
}

char** splitline(char* cmd) {
	if (cmd[0] == '\0' || cmd == NULL)
		return NULL;
  /* Lagre kommandoen til historien array */
	history[history_num++] = strdup(cmd);
	char** ret;
	char* cur = cmd;
	char* left;
	int count = 0;
	if ((ret = malloc(MAXLINE)) == NULL) {
		perror("split");
		return NULL;
	}
	/* Split kommandoen i henhold til mellomromstegn */
	while (*cur != '\0') {
		while (*cur == ' ' || *cur == '\t')
			cur++;
		if (*cur == '\0')
			break;
		else {
			int len = 0;
			left = cur;
			while (!(*cur == ' ' || *cur == '\t') && *cur != '\0') {
				cur++;
				len++;
			}
			char* t = malloc_clear(len + 1);
			strncpy(t, left, len);
			t[len] = '\0';
			ret[count] = t;
			count++;
		}
	}
	ret[count] = NULL;
	return ret;
}

/* Leser en kommando og returnerer til slutt en rekke strenger etter at den har blitt delt  */
char** read_command() {
	memset(cmdline, '\0', MAXLINE);
	if (fgets(cmdline, MAXLINE, stdin) == 0) {
		printf("\n");
		exit(0);
	}
	cmdline[strlen(&cmdline[0]) - 1] = '\0';
	/* Split lese kommandolinjen direkte */
	return (splitline(cmdline));
}

/* Bestemmer om en streng er i en rekke strenger, hovedsakelig brukt til å bestemme interne kommandoer */
int in(char* a, char* b[], int n) {
	int i;
	for (i = 0; i < n; i++) {
		if (!strcmp(a, b[i]))
			return (i + 1);
	}
	return 0;
}

/* Calculates the length of the command, argc */
int length(char** cmd) {
	int count = 0;
	while (cmd[count] != NULL)
		count++;
	return count;
}

/* Get the current myshell run path, not the work path */
char* get_path() {
	memset(pathname, '\0', MAXSIZE);
	memset(processname, '\0', MAXSIZE);
	char* path_end;
	/* Read the current run path */
	if (readlink("/proc/self/exe", pathname, MAXSIZE) <= 0)
		return NULL;
	/* Determine the position by '/'  */
	path_end = strrchr(pathname, '/');
	if (path_end == NULL)
		return NULL;
	path_end++;
	strcpy(processname, path_end);
	*path_end = '\0';
	char* ret = malloc_clear(strlen(pathname) + strlen(processname) + 1);
	strcat(ret, pathname);
	strcat(ret, processname);
	return ret;
}

/* Get the path to display, such as "myshell:~/$" */
char* get_display_path() {
	char* home = getenv("HOME");
	memset(buffer, 0, MAXLINE);
	getcwd(buffer, MAXLINE);
	char* curdir = malloc_clear(strlen(buffer) + 1);
	strcpy(curdir, buffer);
	/* If the front part of the display path is the same as the main directory, use '~' instead of */
	if (strncmp(curdir, home, strlen(home)) == 0) {
		char* disdir = malloc_clear(strlen(buffer) - strlen(home) + 1);
		strcpy(disdir, curdir + strlen(home));
		free(curdir);
		curdir = malloc_clear(strlen(buffer) - strlen(home) + 2);
		strcat(curdir, "~");
		strcat(curdir, disdir);
		free(disdir);
	}
	/* Add a prompt such as "myshell:", "$" to the display path */
	char* retdir = malloc_clear(strlen(curdir) + strlen("myshell:") + strlen("$ ") + 1);
	strcat(retdir, "myshell:");
	strcat(retdir, curdir);
	strcat(retdir, "$ ");
	free(curdir);
	return retdir;
}

/* Set the environment variable, the format is "name=path" */
void set_path(char* name, char* path) {
	environ[environ_num] = malloc_clear(strlen(name) + strlen(path) + 2);
	strcat(environ[environ_num], name);
	strcat(environ[environ_num], "=");
	strcat(environ[environ_num], path);
	environ_num++;
}

/* Initialize all environment variables and working paths */
void init() {
	head = tail = NULL;
	char* shell = get_path();
	char* home = getenv("HOME");
	/* Initialize the "HOME", "PWD", "shell" environment variables */
	set_path("HOME", home);
	set_path("PWD", home);
	set_path("shell", shell);
	free(shell);
	chdir(home);
}

/* Determine whether it is an internal command, check by the helper function in */
int is_internal_cmd(char** cmd) {
	if (cmd == NULL)
		return 0;
	else
		return(in(cmd[0], internal_cmd, length(internal_cmd)));
}

/* If the format of a variable is "$x", then replace it with its value */
void my_convert(char* x) {
	if (x[0] == '$') {
		/* First traverse all common variables */
		char** p = variable;
		while (*p != NULL) {
			char* tmp = malloc_clear(strlen(*p) + 2);
			strcat(tmp, "$");
			strcat(tmp, *p);
			int comp_len = strlen(x);
			/* Compare whether the left value is the same, that is, whether the variable names are the same */
			if (strncmp(tmp, x, comp_len) == 0) {
				free(x);
				x = malloc_clear(strlen(tmp + comp_len + 1) + 1);
				strcpy(x, tmp + comp_len + 1);
				free(tmp);
				return;
			}
			free(tmp);
			p++;
		}
		/* Traverse all environment variables */
		p = environ;
		while (*p != NULL) {
			char* tmp = malloc_clear(strlen(*p) + 2);
			strcat(tmp, "$");
			strcat(tmp, *p);
			int comp_len = strlen(x);
			if (strncmp(tmp, x, comp_len) == 0) {
				free(x);
				x = malloc_clear(strlen(tmp + comp_len + 1) + 1);
				strcpy(x, tmp + comp_len + 1);
				free(tmp);
				return;
			}
			free(tmp);
			p++;
		}
	}
}

/* Sets a normal variable. The format of the string input is "a=b" */
void my_variable(char* s) {
	unsigned char tmp;
	char *l, *r, *left, *right;
	l = strchr(s, '=');
	right = strdup(l + 1);
	tmp = (unsigned char)(strchr(s, '=') - s);
	r = (tmp > 0) ? strndup(s, tmp) : strdup(s);
	left = r;
	my_convert(right);
	char** p = variable;
	/* If this variable already exists, update its value */
	while (*p != NULL) {
		if (strncmp(s, *p, strlen(left)) == 0) {
			free(*p);
			*p = malloc_clear(strlen(left) + strlen(right) + 2);
			strcat(*p, left);
			strcat(*p, "=");
			strcat(*p, right);
			break;
		}
		p++;
	}
	/* If the variable does not exist, then simply insert */
	if (*p == NULL) {
		variable[variable_num] = malloc_clear(strlen(left) + strlen(right) + 2);
		strcat(variable[variable_num], left);
		strcat(variable[variable_num], "=");
		strcat(variable[variable_num], right);
		variable_num++;
	}
	free(left);
	free(right);
}

/* Show all tasks in the background  */
void my_job() {
	job* p = head;
	int count = 1;
	if (head != NULL) {
		do {
			printf("[%d]\t%d\t%s\t%s", count++, p->pid, p->state, p->cmd);
			printf("\n");
			p = p->next;
		} while (p != NULL);
	}
	else
		printf("jobs: no job\n");
}

/* Add task to linked list */
void add_job(job* x) {
	x->next = NULL;
	/* If it is the first inserted pointer */
	if (head == NULL) {
		head = x;
		tail = x;
	}
	else {
		tail->next = x;
		tail = x;
	}
}

/* Remove tasks from the linked list */
void del_job(job* x) {
	job *p, *q;
	int pid = x->pid;
	p = q = head;
	if (head == NULL)
		return;
	while (p->pid != pid && p->next != NULL)
		p = p->next;
	if (p->pid != pid)
		return;
	/* If the header is deleted */
	if (p == head)
		head = head->next;
	if (p == tail)
		tail = tail->next;
	else {
		while (q->next != p)
			q = q->next;
		if (p == tail) {
			tail = q;
			q->next = NULL;
		}
		else
			q->next = p->next;
	}
	free(p);
}

/* Hangs into the child process */
void my_ctrlz() {
	job *p;
	int i = 1;
	/* If it is a parent process, skip it directly */
	if (son_pid == 0) {
		return;
	}
	if (head != NULL) {
		p = head;
		while (p->pid != son_pid && p->next != NULL)
			p = p->next;
		if (p->pid == son_pid) {
			strcpy(p->state, "stopped");
		}
		else {
			/* New task pointer */
			p = (job*)malloc(sizeof(job));
			strcpy(p->state, "stopped");
			strcpy(p->cmd, history[history_num - 1]);
			p->pid = son_pid;
			add_job(p);
		}
	}
	else {
		p = (job*)malloc(sizeof(job));
		strcpy(p->state, "stopped");
		strcpy(p->cmd, history[history_num - 1]);
		p->pid = son_pid;
		add_job(p);
	}
	/* Conversion process status */
	kill(son_pid, SIGSTOP);
	for (p = head; p->pid != son_pid; p = p->next)
		i++;
	/* Print current information */
	printf("\n[%d]\t%s\t%s\n", i, tail->state, tail->cmd);
	son_pid = 0;
	return;
}

/* Processing signal function */
void sig_handler(int p) {
	if (p == SIGINT) {
		/* invalidates the ctrl+c signal during operation */
		if (son_pid != 0)
			kill(son_pid, SIGTERM);
	}
	else if (p == SIGTSTP) {
		/* Handling the signal function of ctrl+z */
		my_ctrlz();
	}
}

/* Move a specific task to the background to execute*/
void my_bg(char** cmd) {
	int argc = length(cmd);
	char** argv = cmd;
	if (argv[1] == NULL) {
		printf("bg: no such task\n");
		return;
	}
	int job_num = atoi(argv[1]);
	int i;
	job* p = head;
	/* Find the corresponding task based on the pointer */
	for (i = 1; i < job_num && p != NULL; i++)
		p = p->next;
	if (i != job_num) {
		printf("bg: out of range\n");
		return;
	}
	/* Replace process status */
	kill(p->pid, SIGCONT);
	strcpy(p->state, "running");
}

void my_exec(char** cmd) {
	int argc = length(cmd);
	char** argv = cmd;
	/* Open child process execution command */
	pid_t pid = fork();
	if (pid < 0) {
		perror("exec");
	}
	else if (pid == 0) {
		execute(&argv[1]);
		exit(1);
	}
	else {
		waitpid(pid, NULL, 0);
	}
}

/*  Move a specific task to the foreground to execute */
void my_fg(char** cmd) {
	sigprocmask(SIG_UNBLOCK, &son_set, NULL);
	int argc = length(cmd);
	char** argv = cmd;
	if (argv[1] == NULL) {
		printf("fg: no such task\n");
		return;
	}
	int job_num = atoi(argv[1]);
	int i;
	job* p = head;
	/* Find specific tasks based on the pointer */
	for (i = 1; i < job_num && p != NULL; i++)
		p = p->next;
	if (i != job_num) {
		printf("fg: out of range\n");
		return;
	}
	strcpy(p->state, "running");
	son_pid = p->pid;
	/* Replace process status */
	kill(p->pid, SIGCONT);
	del_job(p);
	waitpid(p->pid, NULL, 0);
}

/* Kill a specific process */
void my_kill(char** cmd) {
	int argc = length(cmd);
	char** argv = cmd;
	if (argv[1] == NULL) {
		printf("kill: no such task\n");
		return;
	}
	pid_t pid = atoi(argv[1]);
	job* p = head;
	while (p != NULL) {
		if (p->pid == pid)
			break;
		p = p->next;
	}
	/* If it is running in the background, delete its pointer in the linked list */
	if (p != NULL) {
		del_job(p);
	}
	/* Kill the process */
	kill(pid, SIGKILL);
}

/* Display current history command */
void my_history() {
	int i = 0;
	for (i = 0; i < history_num; i++) {
		printf("[%d]\t%s\n", i + 1, history[i]);
	}
}

/* Clear current page */
void my_clear() {
	printf("%s", "\033[1H\033[2J");
}

/* exits shell */
void my_quit() {
	exit(0);
}

/* All commands after skipping */
void my_continue() {
	run_flag = 0;
}

/* Read the file and read it line by line */
void my_readline(char** ret, char* file_name) {
	FILE* in;
	int i = 0;
	memset(buffer, '\0', MAXLINE);
	if ((in = fopen(file_name, "r")) != NULL) {
		/* Not at the end of the file */
		while (fgets(buffer, sizeof(buffer), in)) {
			ret[i] = malloc_clear(sizeof(char) * MAXLINE);
			if (ret[i] == NULL) {
				printf("shell: fail to apply space\n");
				return;
			}
			strcpy(ret[i], buffer);
			ret[i][strlen(ret[i]) - 1] = '\0';
			i++;
		}
	}
	ret[i] = NULL;
	fclose(in);
}

/* Execute file script */
void my_shell(char** cmd) {
	int argc = length(cmd);
	char** argv = cmd;
	/* If the parameter is missing, the user is constantly prompted to enter the file parameters */
	while (argv[1] == NULL) {
		printf("$ ");
		char** read = read_command();
		if (read != NULL && strlen(read[0]) != 0) {
			int j = 0;
			while (read[j] != NULL) {
				argv[j + 1] = malloc_clear(strlen(read[j]) + 1);
				strcpy(argv[j + 1], read[j]);
				j++;
			}
			argv[j + 1] = NULL;
		}
		free(read);
	}
	/* Set the corresponding file parameters */
	argc = length(argv);
	char* shell_line[MAXLINE];
	char* file = argv[1];
	my_paras(argv);
	my_readline(shell_line, file);
	int i = 0;
	/* Execute commands line by line */
	while (shell_line[i] != NULL) {
		char** split_line = splitline(shell_line[i]);
		execute(split_line);
		if (!run_flag) {
			my_clear_paras();
			run_flag = 1;
			return;
		}
		free(split_line);
		free(shell_line[i]);
		i++;
	}
	/* Clear script variables */
	my_clear_paras();
}

/*  */
int is_normal(char** cmd) {
	return (!(is_internal_cmd(cmd)));
}

/* External command, call execvp to execute */
void my_normal(char** cmd) {
	execvp(cmd[0], cmd);
}

/* Internal command */
void my_internal(char** cmd) {
	char* line = cmd[0];

	if (!strcmp(line, "bg")) {
		my_bg(cmd);
		return;
	}
	if (!strcmp(line, "fg")) {
		my_fg(cmd);
		return;
	}
	if (!strcmp(line, "jobs")) {
		my_job();
		return;
	}
	if (!strcmp(line, "kill")) {
		my_kill(cmd);
		return;
	}
	if (!strcmp(line, "exec")) {
		my_exec(cmd);
		return;
	}
	if (!strcmp(line, "myshell")) {
		my_shell(cmd);
		return;
	}
	if (!strcmp(line, "set")) {
		my_set(cmd);
		return;
	}
	if (!strcmp(line, "unset")) {
		my_unset(cmd[1]);
		return;
	}
	if (!strcmp(line, "umask")) {
		my_umask(cmd);
		return;
	}
	if (!strcmp(line, "quit")) {
		my_quit();
		return;
	}
	if (!strcmp(line, "help")) {
		my_help();
		return;
	}
	if (!strcmp(line, "more")) {
		my_more(cmd);
		return;
	}
	if (!strcmp(line, "test")) {
		my_test(&cmd[1]);
		return;
	}
	if (!strcmp(line, "atest")) {
		my_atest(&cmd[1]);
		return;
	}
	if (!strcmp(line, "shift")) {
		my_shift();
		return;
	}
	if (!strcmp(line, "continue")) {
		my_continue();
		return;
	}
	if (!strcmp(line, "mv")) {
		my_mv(cmd);
		return;
	}
	if (!strcmp(line, "mkdir")) {
		my_mkdir(cmd);
		return;
	}
	if (!strcmp(line, "rm")) {
		my_rm(cmd);
		return;
	}
	if (!strcmp(line, "rmdir")) {
		my_rmdir(cmd);
		return;
	}
	if (!strcmp(line, "date")) {
		my_date();
		return;
	}
	if (!strcmp(line, "history")) {
		my_history();
		return;
	}
	if (!strcmp(line, "cp")) {
		my_cp(cmd);
		return;
	}
	if (!strcmp(line, "head")) {
		my_head(cmd);
		return;
	}
	if (!strcmp(line, "tail")) {
		my_tail(cmd);
		return;
	}
	if (!strcmp(line, "touch")) {
		my_touch(cmd);
		return;
	}
}

/* Execute command function */
void execute(char** cmd) {
	if (cmd == NULL)
		return;
	pid_t pid1, pid2;
	int argc = length(cmd);
	char** argv = cmd;
	/* Determine if it is executed in the background */
	if (strcmp(argv[argc - 1], "&") == 0)
		is_back = 1;
	else
		is_back = 0;
	/* Determine if the variable is assigned */
	if (argc == 1 && strchr(argv[0], '=')) {
		my_variable(argv[0]);
		return;
	}
	/* Background execution */
	if (is_back) {
		pid1 = fork();
		if (pid1 < 0) {
			perror("&");
		}
		else if (pid1 == 0) {
			/* Set the "parent" variable */
			char* parent = get_path();
			set_path("parent", parent);
			free(parent);
			argv[argc - 1] = NULL;
			execute(argv);
			exit(0);
		}
		else {
			/* Cancel the mask set */
			sigprocmask(SIG_UNBLOCK, &son_set, NULL);
			son_pid = pid1;
			job *p = (job*)malloc(sizeof(job));
			strcpy(p->state, "running");
			strcpy(p->cmd, argv[0]);
			p->pid = pid1;
			add_job(p);
			kill(pid1, SIGCONT);
		}
	}
	else {
		/* Execute internal commands */
		if (is_internal_cmd(argv) && !is_pipe(argv) && !is_io_redirect(argv)) {
			my_internal(argv);
			return;
		}
		/* Execute internal commands */
		if (is_pipe(argv)) {
			my_pipe(argv);
			return;
		}
		/* Execute with redirect command */
		if (is_io_redirect(argv)) {
			my_redirect(argv);
			return;
		}
		/* Execute external command */
		if (is_normal(argv)) {
			pid2 = fork();
			if (pid2 < 0) {
				perror("myshell");
			}
			else if (pid2 == 0) {
				char* parent = get_path();
				set_path("parent", parent);
				free(parent);
				my_normal(argv);
			}
			else {
				sigprocmask(SIG_UNBLOCK, &son_set, NULL);
				son_pid = pid2;
				waitpid(pid2, NULL, 0);
			}
			return;
		}
	}
}
