// some more ret2win
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void win()
{
    puts("You win!");
    execve("/bin/sh", NULL, NULL);
    exit(201);
}

{{cruff_functions}}


int main()
{
    puts("Welcome to: {{ challenge_name }}");
    setvbuf(stdout,NULL,_IONBF,0);

    char buf[] = "0xDEADBEEF";
    char user_input[{{ buf_size }}];

    gets(user_input);

    printf("You lose!\n");
    return 0;
}
