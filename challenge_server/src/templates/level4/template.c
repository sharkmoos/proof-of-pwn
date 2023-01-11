// ret2libc + canary
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int streq(char* left, char* right, int count) {
  for (int cursor = 0; cursor < count; cursor++) {
    char l = left[cursor];
    char r = right[cursor];

    if (l != r) return 0;
  }

  return 1;
}

char* generate_string()
{
    char *string = (char*) malloc({{ random_string_len }} + 1);
    {% for i in range(random_string_len) %}
      string[{{ i }}] = '{{ random_string[i] }}';
    {% endfor %}
    string[{{ random_string_len }}] = '\0';
    return string;
}

int main()
{
    puts("Welcome to: {{ challenge_name }}");
    setvbuf(stdout,NULL,_IONBF,0);

    struct
    {
        char *random_ptr;
        char buf[{{ buf_size }}];
        char canary[{{ random_string_len }}];
    } data;

    data.random_ptr = generate_string();
    strcpy(data.canary, data.random_ptr);

    char user_input[{{ buf_size }}];

    puts("I am challenge {{ challenge_name }} \nGive me your best!");

    gets(data.buf);

    if (!streq(data.canary, data.random_ptr, {{ random_string_len }}))
    {
        puts("HACKING DETECTED. EXITING WITH EXTREME PREJUDICE");
        exit(-1);
    }
    puts("Valid");
    return 0;
}
