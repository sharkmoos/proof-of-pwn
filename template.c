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

int main()
{
    char canary[] = "{{ random_string }}";
    char user_input[{{ size }}];

    puts("I am challenge {{ challenge_name }} \nGive me your best!");

    gets(user_input);

    if (!streq(canary, "{{ random_string }}", {{ random_string_len }}))
    {
        puts("HACKING DETECTED. EXITING WITH EXTREME PREJUDICE");
        exit(-1);
    }
    puts("Valid");
    return 0;
}
