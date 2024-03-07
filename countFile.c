/*
 * This functiom reads directory and count files
 * Store the directory name and the number of non-dir files 
 */

// Storing dirname and No of files

typedef struct cStore{
    char dName[100];
    int fPresent;
};

int fCount(void){
    const char dN[];
    if(getcwd(dN, sizeof(dN)) == dN) return dN;
    
    struct dirent *entry;
    struct stat statbuf;
    DIR *dp;

    if((dp = opendir(dN)) == NULL) return;
    while((entry=readdir(dp))!= NULL){
        lstat(entry.d_name, &statbuf);
        int n = sizeof(entry);
        for(int i=0;i<=n;++i){
            
        }
    }

    /*
        while((entry = readdir(dp)) != NULL){
        lstat(entry->d_name, &statbuf);
        if(S_ISDIR(statbuf.st_mode)){
            if(strcmp(".", entry->d_name) == 0 || strcmp("..",entry->d_name) == 0) continue;
            printf("%*s%s/\n",depth,"",entry->d_name);
        }else printf("%*s%s\n",depth,"",entry->d_name);
    }
   */

} 