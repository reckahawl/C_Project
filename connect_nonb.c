int connect_nonb(int sockfd, const SA *saptr, socklen_t salen, int nsec){
    int     flags, n, error;
    socklen_t   len;
    fd_set      rset, wset;
    struct timeval  tval;

    flags = Fcntl(sockfd, F_GETFL, 0);
    Fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);

    error=0;
    if((n=connect(sockfd,saptr,salen)) < 0) \
        if(errno != EINPROGRESS) return -1;
    
    /* Do anything while connect is working */
    if(n==0) goto done;

    FD_ZERO(&rset);
    FD_SET(sockfd, &rset);
    wset = rset;
    tval.tv_sec = nsec;
    tval.tv_usec = 0;

    if((n=Select(sockfd+1, &rset, &wset, NULL, nsec ? &tval : NULL)) == 0){
        close(sockfd); // use shutdown for more efficiency in data transfer
        errno = ETIMEDOUT;
        return -1;
    }

    if(FD_ISSET(sockfd, &rset) || FD_ISSET(sockfd, &wset)){
        len = sizeof error ;
        if(getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, &len) < 0) return -1;   
    }else err_quit("");

    done:
        Fcntl(sockfd, F_SETFL, flags);

        if(error){
            close(sockfd);
            errno = error;
            return -1;
        }
        return 0;
}