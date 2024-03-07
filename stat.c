#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>


typedef int Myfunc(const char *, const struct stat *, int);

static Myfunc myfunc;
static int myftw(char *, Myfunc *);
static int dopath(Myfunc *);

static long nreg, ndir, nblk, nchr, nfifo, nslink, nsock, nton;

int main(int argc, char *argv[]){
    int i, ret;
    /*
    struct stat buf;
    char *ptr;

    for(i=1; i<argc; i++){
        printf("%s", argv[i]);
        if(lstat(argv[i], &buf) < 0){
            perror("lstat error");
            continue;
        }
        if(S_ISREG(buf.st_mode)) ptr = "regular file";
        else if(S_ISDIR(buf.st_mode)) ptr = "directory";
        else if(S_ISCHR(buf.st_mode)) ptr = "character";
        else if(S_ISBLK(buf.st_mode)) ptr = "block special";
        else if(S_ISFIFO(buf.st_mode)) ptr = "fifo special";
        else if(S_ISLNK(buf.st_mode)) ptr = "link special";
        else if(S_ISSOCK(buf.st_mode)) ptr = "socket special";
        else ptr = "unknown mode";
        printf("%s\n", ptr);
    }

    */
    if(argc != 2) perror("Invalid");

    ret = myftw(argv[1], myfunc);

    ntot = nreg + ndir + nfifo + nblk + nslink + nsock;

    if(ntot == 0) ntot = 1;

    printf("regular files = %7ld, %5.2f %%\n", nreg,nreg*100.0/ntot);
    printf("directories= %7ld, %5.2f %%\n", ndir,ndir*100.0/ntot);
    printf("block special = %7ld, %5.2f %%\n", nblk,nblk*100.0/ntot);
    printf("char special= %7ld, %5.2f %%\n", nchr,nchr*100.0/ntot);
    printf("FIFOs= %7ld, %5.2f %%\n", nfifo,nfifo*100.0/ntot);
    printf("symbolic links = %7ld, %5.2f %%\n", nslink,nslink*100.0/ntot);
    printf("sockets= %7ld, %5.2f %%\n", nsock,nsock*100.0/ntot)
    exit(ret);
}

#define FTW_F 1 //file other than directory
#define FTW_D 2 //directory
#define FTW_DNR 3 //directory that cant read
#define FTW_NS 4    // file we cant stat

static char *fullpath;
static size_t pathlen;

static int myftw(char *pathname, Myfunc *func){
    fullpath = (char *)malloc(pathlen+1);

    if(pathlen <= strlen(pathlen)){
        pathlen = strlen(pathname) *2;
        if((fullpath = realloc(fullpath, pathlen)) == NULL) perror("malloc");
    }
    strcpy(fullpath, pathname);
    return(dopath(func));
}


static int dopath(Myfunc *func){
    struct stat sbuf;
    struct dirent *dirp;
    DIR    *dp;
    int    ret, n;

    if(lstat(fullpath, &sbuf) < 0) return(func(fullpath, &sbuf, FTW_NS));

    if(S_ISDIR(sbuf.st_mode) == 0) return(func(fullpath, &sbuf, FTW_F));

    if((ret = func(fullpath, &sbuf, FTW_D)) != 0) return(ret);

    n = strlen(fullpath);
    if( n + NAME_MAX + 2 > pathlen){
        pathlen *= 2;
        if((fullpath = realloc(fullpath,pathlen)) == NULL) perror("realloc");
    }
    fullpath[n++] = '/';
    fullpath[n] = 0;

    if((dp = opendir(fullpath)) == NULL) return(func(fullpath, &sbuf,FTW_DNR));

    while((dirp = readdir(dp)) != NULL){
        if(strcmp(dirp->d_name, ".") == 0 || strcmp(dirp->d_name, "..") == 0) continue;
        strcpy(&fullpath[n], dirp->d_name);
        if((ret = dopath(func)) != 0) break;
    }
    fullpath[n-1] = 0;

    if(closedir(dp) < 0) perror("closed");

    return(ret);
}

static int
myfunc(const char *pathname, const struct stat *statptr, int type)
{
    switch (type) {
    case FTW_F:
        switch (statptr->st_mode & S_IFMT) {
        case S_IFREG:
            nreg++;
            break;
        case S_IFBLK:
            nblk++;
            break;
        case S_IFCHR:
            nchr++;
            break;
        case S_IFIFO:
            nfifo++;
            break;
        case S_IFLNK:
            nslink++;
            break;
        case S_IFSOCK: nsock++;
            break;
        case S_IFDIR:
            /* directories should have type = FTW_D */
            err_dump("for S_IFDIR for %s", pathname);
        }
        break;
    case FTW_D:
        ndir++;
        break;
    case FTW_DNR:
        err_ret("can’t read directory %s", pathname);
        break;
    case FTW_NS:
        err_ret("stat error for %s", pathname);
        break;
    default:
        err_dump("unknown type %d for pathname %s", type, pathname);
    }
    return(0);
}



int changemode(void){
    struct stat statbuf;

    // turn on set-group-id and turn of group execute
    if(stat("foo", &statbuf) < 0) perror("perror");

    if(chmod("foo", (statbuf.st_mode & ~S_IXGRP) | S_ISGID) < 0) perror("perror");

    // set absolute mode to rw-r--r--
    if(chmod("bar",S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)<0) perror("perror");

    exit(0);
}
