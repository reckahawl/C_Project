// condition ? expre1 : expre2
//x = y>7 ? 35 : 50
/*
if(y>7) x=35;
else x =50;


int main(){
    double total_price;
    float unit_price;
    float quantity;
    unit_price = 3.50;


    total_price = unit_price*quantity*(quantity>10 ? 1.0 : 0.95)   
}
*/


#include <stdio.h>
//#include <ctypes.h>
#include <stdlib.h>
#include <stdbool.h>

const int LEGNTH = 80;
int main(void)
{
   // const double unit_price = 3.50; /* Unit price in dollars*/
   // const double discount1 = 0.05; /* Discount for more than 10 */
    //const double discount2 = 0.1; /* Discount for more than 20 */
   // const double discount3 = 0.15; /* Discount for more than 50 */
   // double total_price = 0.0;
   // int quantity = 0;
   // printf("Enter the number that you want to buy:");
   // scanf(" %d", &quantity);
   // total_price = quantity*unit_price*(1.0 - (quantity>50 ? discount3 : (quantity>20 ? discount2 : (quantity>10 ? discount1 : 0.0))));
    //printf("The price for %d is $%.2f\n", quantity, total_price);
   // return 0;
    //char another_game = 'Y';

    char *proverb[] = {"Many a mickle makes a muckle.\n",
        "Too many cooks spoil the broth.\n",
        "He who laughs last didn't get the joke in"
        " the first place.\n"};
    char more[LEGNTH];
    FILE *pfile = NULL;
    char *filename = "f.txt";

    if(!(pfile = fopen(filename, "w"))){
        printf("%s",filename);
        exit(1);

    }
    int count = (sizeof(proverb)/sizeof(proverb[0]));
    for(int i =0; i<count; i++){
        fputs(proverb[i], pfile);
    }
    fclose(pfile);

    if(!(pfile = fopen(filename, "a"))){
        exit(1);
    }
    while(true){
        fgets(more, LEGNTH, stdin);
        if(more[0] == '\n') break;
        fputs(more, pfile);
    }
    fclose(pfile);
    if(!(pfile = fopen(filename, "r"))) exit(1);
    while(fgets(more, LEGNTH, pfile)){
        printf("%s", more);
        fclose(pfile);
        remove(filename);
        return 0;}
}


