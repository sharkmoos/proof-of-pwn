#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char random_string[] = "{{ random_string }}";
char user_input[{{ size }}];
ssize_t compare_size = (sizeof(user_input) / sizeof(char) + {{ random_increase }}  );

int main()
{
    puts("I am challenge {{ challenge_name }} \nGive me your best!");
    gets(user_input);

    if ( strlen(user_input) != compare_size )
    {
        printf("Got length %d but wanted %d", strlen(user_input), compare_size);
        exit(0);
    }

    for ( int i=0; i < {{ random_string_len }}; i++ )
    {
        if ( random_string[i] != user_input[i] )
            exit(0);
    }
    exit(1);
}
