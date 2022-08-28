#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char random_string[] = "vrzcdnaxfhrlklivuxt";
char user_input[158];
ssize_t compare_size = (sizeof(user_input) / sizeof(char) + 38  );

int main()
{
    puts("I am challenge binary_0 \nGive me your best!");
    gets(user_input);

    if ( strlen(user_input) != compare_size )
    {
        printf("Got length %d but wanted %d", strlen(user_input), compare_size);
        exit(0);
    }

    for ( int i=0; i < 19; i++ )
    {
        if ( random_string[i] != user_input[i] )
            exit(0);
    }
    exit(1);
}