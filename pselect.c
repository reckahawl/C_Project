int pselect(int nfds, fd_set *rset, fd_set *wset, fd_set *xset, const struct timespec *ts, const sigset_t *sigmask){
    int     n;
    struct  timeval tv;
    sigset_t    savemask;

    if(ts != NULL){
        tv.tv_sec = ts->tv_sec;
        tv.tv_usec = ts->tv_nsec/1000;
    }

    sigprocmask(SIG_SETMASK, sigmask, &savemask);
    n = select(nfds, rset, wset, xset, (ts == NULL) ? NULL : &tv);
    sigprocmask(SIG_SETMASK, &savemask, NULL);

    return n;
}