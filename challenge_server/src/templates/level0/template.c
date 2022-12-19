// just ret2win
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void win()
{
    puts("You win!");
    execve("/bin/sh", 0, 0);
}

{{cruff_functions}}

int main()
{
    puts("Welcome to: {{ challenge_name }}");
    setvbuf(stdout,NULL,_IONBF,0);
    setvbuf(stdin,NULL,_IONBF,0);
    char buf[] = "0xDEADBEEF";
    char user_input[{{ buf_size }}];

    gets(user_input);

    if (!strcmp(buf, "0xDEADBEEF") == 0)
    {
        win();
    }
    printf("You lose!\n");
    exit(0);

}
