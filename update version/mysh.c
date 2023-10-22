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

/* Calculates the length of the command, argc */
int length(char** cmd) {
	int count = 0;
	while (cmd[count] != NULL)
		count++;
	return count;
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

/* Set the environment variable, the format is "name=path" */
void set_path(char* name, char* path) {
	environ[environ_num] = malloc_clear(strlen(name) + strlen(path) + 2);
	strcat(environ[environ_num], name);
	strcat(environ[environ_num], "=");
	strcat(environ[environ_num], path);
	environ_num++;
}


char* get_display_line() {
  static int command_number = 0;
  command_number++;
	char* command_num_char = malloc_clear(sizeof(char)*(int)log10(command_number));
	sprintf(command_num_char, "%d", command_number);
	char* user = malloc_clear(10*sizeof(char));
	user=getlogin();
	/* Add a prompt such as "myshell:", "$" to the display path */
	char* retline = malloc_clear(strlen(user) + strlen("@mysh ") + strlen(command_num_char) + 1);
	strcat(retline, user);
	strcat(retline, "@mysh ");
	strcat(retline, command_num_char);
	free(user);
	free(command_num_char);
	return retline;
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


int is_internal_cmd(char** cmd) {
	if (cmd == NULL)
		return 0;
	else
		return(in(cmd[0], internal_cmd, length(internal_cmd)));
}

int is_normal(char** cmd) {
	return (!(is_internal_cmd(cmd)));
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

/* exits shell */
void my_quit() {
	exit(0);
}

/* Display current history command */
void my_history() {
	int i = 0;
	for (i = 0; i < history_num; i++) {
		printf("[%d]\t%s\n", i + 1, history[i]);
	}
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
	if (!strcmp(line, "history")) {
		my_history();
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
		if (is_internal_cmd(argv)) {
			my_internal(argv);
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
