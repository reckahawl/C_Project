#include <sys/inotify.h>
#include <limits.h>

static void displayInotifyEvent(struct inotify_event *i){
    printf("wd = %2d; ",i->wd);
    if(i->cookie > 0) printf("cookie =%4d; ", i->cookie);

    printf("mask = ");
if (i->mask & IN_ACCESS) printf("IN_ACCESS ");
if (i->mask & IN_ATTRIB) printf("IN_ATTRIB ");
if (i->mask & IN_CLOSE_NOWRITE) printf("IN_CLOSE_NOWRITE ");
if (i->mask & IN_CLOSE_WRITE) printf("IN_CLOSE_WRITE ");
if (i->mask & IN_CREATE) printf("IN_CREATE ");
if (i->mask & IN_DELETE) printf("IN_DELETE ");
if (i->mask & IN_DELETE_SELF) printf("IN_DELETE_SELF ");
if (i->mask & IN_IGNORED) printf("IN_IGNORED ");
if (i->mask & IN_ISDIR) printf("IN_ISDIR ");
if (i->mask & IN_MODIFY) printf("IN_MODIFY ");
if (i->mask & IN_MOVE_SELF) printf("IN_MOVE_SELF ");
if (i->mask & IN_MOVED_FROM) printf("IN_MOVED_FROM ");
if (i->mask & IN_MOVED_TO) printf("IN_MOVED_TO ");
if (i->mask & IN_OPEN) printf("IN_OPEN ");
if (i->mask & IN_Q_OVERFLOW) printf("IN_Q_OVERFLOW ");
if (i->mask & IN_UNMOUNT)   printf("IN_UNMOUNT ");

if(i->len > 0) printf();
}