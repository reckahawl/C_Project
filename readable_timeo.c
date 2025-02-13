int readable_timeo(int fd, int sec){
    fd_set      rset;
    struct timeval tv;

    FD_ZERO(&rset);
    FD_SET(fd, &rset);

    tv.tv_sec = sec;
    tv.tv_usec = 0;

    return select(fd+1, &rset, NULL, NULL, &tv);

}

int Readable_timeo(int fd){
    // Error Manag
}



ssize_t readn(int fd, void *vptr, size_t n){
    size_t  nleft;
    ssize_t nread;
    char *ptr;

    ptr = vptr;
    nleft = n;
    while(nleft>0){
        if((nread = read(fd,ptr,nleft)) < 0){
            if(errno == EINTR) nread=0;
            else return -1;
        }else if(nread==0) break;
        nleft -= nread;
        ptr += nread;
    }
    return n-nleft;
}


static int read_cnt;
static char *read_ptr;
static char read_buf[MAXLINE];

static ssize_t my_read(int fd, char *ptr){
    if(read_cnt <= 0){
again:
        if((read_cnt = read(fd, read_buf,sizeof read_buf)) < 0){
            if(errno == EINTR) goto again;
            return -1;
        } else if(read_cnt == 0) return 0;
        read_ptr = read_buf;
    }
    read_cnt--;
    *ptr = *read_ptr++
}

ssize_t readline(int fd, void *vptr, size_t maxlen){
    ssize_t     n, rc;
    char    c,  *ptr;

    ptr=vptr;
    for(n=1; n<maxlen; n++){
        if((rc=my_read(fd, &c)) == 1){
            *ptr++ = c;
            if(c=='\n') break;
        }else if(rc == 0){
            *ptr = 0;
            return n - 1;
        }else return -1;
    }
    *ptr = 0;
    return n;
}