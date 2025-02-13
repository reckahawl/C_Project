#include <syslog.h>

#define MAXFD 64

extern int daemon_proc;

int daemon_init(const char *pname, int facility){
    int         i;
    pid_t       pid;

    if((pid=Fork()) < 0) return -1;
    else if(pid) _exit(0); // Parent terminates;

    // Child 1 continues 
    if(setsid() < 0) return -1;

    Signal(SIGHUP, SIG_IGN);
    if((pid=Fork()) < 0) return -1;
    else if(pid) _ exit(0); // child 1 terminate

    daemon_proc = 1;

    chdir("/");


	/* redirect stdin, stdout, and stderr to /dev/null */
	open("/dev/null", O_RDONLY);
	open("/dev/null", O_RDWR);
	open("/dev/null", O_RDWR);

    openlog(pname, LOG_PID, facility);

	return (0);				/* success */
}