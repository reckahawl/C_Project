//code snippets

int main(int argc, char *argv[]){
    uid_t uid;
    struct passwd *pwd;

    uid = getuid();
    printf("User UID is %d\n",(int)uid);
    if(!(pwd=getpwuid(uid))){
        printf("Unable to get User pass rec");
        endpwent();
        return 1;
    }
    printf("User home dir is %s\n",pwd->pw_dir);
    endpwent();
    
    return 0;
}

//
extern char **environ;
static char *spc_preserv_envirn[]={"TZ",0};

void spc_sanitize_environ(int preservec, char **preservev){
    int i;
    char **new_environ,*ptr,*value,*var;
    size_t arr_size=1,arr_ptr=0,len,new_size=0;

    for(i=0;(var=spc_restricted_environ[i])!=0;i++){
        new_size += strlen(var)+1;
        arr_size++;
    }

    for(i=0;(var=spc_restricted_environ[i])!=0;i++){
        if(!(value=getenv(var))) continue;
        new_size += strlen(var) + strlen(value) +2;
        arr_size++;
    }
    if(preservec && preservev){
        for(i=0;i<preservec&&(var=preservev[i])!=0;i++){
            if(!(value=getenv(var)))continue;
            new_size+=strlen(var) + strlen(value) +2;
            arr_size++;
        }
    }
    new_size += (arr_size * sizeof(char *));
    if(!(new_environ = (char **)malloc(new_size))) abort();
    new_environ[arr_size -1]=0;
    ptr = (char *)new_environ+(arr_size * sizeof(char *));
    for(i=0;(var=spc_restricted_environ[i]) !=0; i++){
        new_environ[arr_ptr++]=ptr;
        len=strlen(var);
        memcpy(ptr,var,len);
        *(ptr+len+1)='=';
        memcpy(ptr +len +2,value, strlen(value)+1);
        ptr += len+strlen(value)+2;
    }
    if(preservec && preservev){
        for(i=0; i<preservec &&(var=preservev[i]) !=0; i++){
            if(!(value = getenv(var))) continue;
            new_environ[arr_ptr++]=ptr;
            len=strlen(var);
            memcpy(ptr, var, len);
            *(ptr+len+1)='=';
            memcpy(ptr+len+2, value,strlen(value)+1);
            ptr+=len+strlen(value)+2;
        }
    }
    environ = new_environ;
}




