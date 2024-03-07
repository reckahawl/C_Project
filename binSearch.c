

//binary search
int binSearch(int key, int list[], int lo, int hi){
    // search for key from list[lo] to list[hi]
    //if found, return its location; otherwise, return -1
    while(lo<=hi){
        int mid = (lo+hi)/2;
        if(key == list[mid]) return mid;
        if(key<list[mid]) hi = mid - 1;
        else lo = mid + 1;
    }
    return -1;
}

// search array of str

int binSearch(int lo, int hi, char key[], int max, char list[][max]){
    //search for key from list[lo] to list[hi]
    //if foun
    while(lo<=hi){
        int mid = (lo + hi)/2;
        int cmp = strcmp(key, list[mid]);
        if(cmp == 0) return mid;
        if(cmo < 0) hi = mid - 1;
        else lo = mid + 1;
    }
    return -1;
}
