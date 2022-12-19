// ret2plt
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char* command_string = "/bin/sh";

void win()
{
    system("echo 'You win!'");
}

{{cruff_functions}}

int main()
{
    puts("Welcome to: {{ challenge_name }}");
    setvbuf(stdout,NULL,_IONBF,0);

    char buf[] = "0xDEADBEEF";
    char user_input[{{ buf_size }}];

    printf("Try to call %s\n> ", command_string);

    gets(user_input);

    if (!strcmp(buf, "0xDEADBEEF") == 0)
    {
        printf("You win!\n");
        return 0;
    }
    else
    {
        printf("You lose!\n");
        exit(0);
    }

}
