// ret2libc + canary
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

{{cruff_functions}}


int main()
{
    puts("Welcome to: {{ challenge_name }}");
    setvbuf(stdout,NULL,_IONBF,0);

    char canary[] = "{{ random_string }}";
    char user_input[{{ buf_size }}];

    puts("I am challenge {{ challenge_name }} \nGive me your best!");

    gets(user_input);

    return 0;
}
