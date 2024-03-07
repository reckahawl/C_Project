
// selection sort

void selectionSort(int list[], int lo, int hi){
    //sort list[lo] to list[hi] ascending order
    int getSmallest(int[], int, int);
    void swap(int[], int, int);
    for(int h = lo; h<hi; h++){
        int s = getSmallest(list, h, hi);
        swap(list, h, s);
    }
}

int getSmallest(int list[], int lo, int hi){
    //return location of smallest from list[lo..hi]
    int small = lo;
    for(int h = lo + 1; h<= hi; h++){
        if(list[h] < list{small}) small = h;
    }
    return small;
}
void swap(int list[], int i, int j){
    //swap elements list[i] and list[j]
    int hold = list[i];
    list[i] = list[j];
    list[j] = hold;
}


// insertion sort

void insertionSort(int list[], int n){
    //sort list[0] to list[n-1] in ascending order
    for(int h=1; h<n; h++){
        int key=list[h];
        int k=h-1; //start comparing with previous
        while(k>=0 && key<list[k]){
            list[k+1] = list[k];
            --k;
        }
        list[k+1] = key;
    }
}

//inserting eleent 

void insertPlace(int newItem, int list[], int n, int m){
    //list[n] to list[m] are sorted
    //insert newItem so that list[n] to list[m+1] are sorted
    int k =m;
    while(k>=n && newItem < list[k]){
        list[k+1] = list[k];
        --k;
    }
    list[k+1]=newItem;
}

// string insSort
void insertionSort3(int lo, int hi, int max, char list[max]){
    //sort string in list[lo] to list[hi] in alphabetical order
    //The maximum string size is max - 1
    char key[max];
    for(int h=lo; h<=hi; h++){
        strcpy(key, list[h]);
        int k = h-1; // comparing with the previous
        while(k >= lo && strcmp(key, list[k])<0){
            strcpy(list[k+1], list[k]);
            --k;
        }
        strcpy(list[k+1], key);
    }
}