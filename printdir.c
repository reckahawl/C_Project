/*
#include <unistd.h>
#include <stdlib.h>

#define BUF 128

char lens[BUF] = {"lens Lewinson is a coder, programmer and a hacker\0\n"};

int main(){
    
    
    write(1,lens, sizeof(lens));
}
*/

#include<stdlib.h>
#include<stdio.h>
#include<unistd.h>
#include<dirent.h>
#include<string.h>
#include<sys/stat.h>

void printdir(char *dir, int depth){
    DIR *dp;
    struct dirent *entry;
    struct stat statbuf;

    chdir(dir);
    if((dp = opendir(dir)) == NULL){
        return;
    }
    while((entry = readdir(dp)) != NULL){
        lstat(entry->d_name, &statbuf);
        if(S_ISDIR(statbuf.st_mode)){
            if(strcmp(".", entry->d_name) == 0 || strcmp("..",entry->d_name) == 0) continue;
            printf("%*s%s/\n",depth,"",entry->d_name);
        }else printf("%*s%s\n",depth,"",entry->d_name);
    }
    chdir("..");
    closedir(dp);
}
int main(int argc, char *argv[]){
    printf("Directory scan of /:\n");
    printdir("/",0);
    printf("done.\n");

    exit(0);
}


