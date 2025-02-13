

int sock_fd(int sockfd){
    struct sockaddr_in *serv;

    bzero(serv, sizeof serv);
    serv.sin_family = AF_INET;
    serv.sin_addr.s_addr = htonl();
    serv.sin_port = htons();


}