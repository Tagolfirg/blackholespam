/* Count the bytes, buffered or unbuffered, Chris Kennedy (C) 2002 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[]) {
  int i, c, b;
  char *string = NULL, *string2 = NULL;
  int strsize, buffered = 0;

  if(argc == 2 && atoi(argv[1]) == 1)
    buffered = 1;

  i = 0;
  while(c = fgetc(stdin)) {
    /* current string size */
    if(string != NULL)
      strsize = strlen(string)+2;
    else 
      strsize = 2;
    /* tmp storage */
    string2 = malloc(strsize);
    strncpy(string2,string,strsize-2);
    /* concatenate new string from old + new byte */
    string = malloc(strsize);
    snprintf(string, strsize, "%s%c", string2, c);
    
    i++;
    if(c == '\n') {
      if(i == 2)
        if(b == 'q')
          break;
      if(i > 1)
        fprintf(stdout, "%sTotal: %d\n", string, i-1);
      i = 0;
      if(buffered == 0) {
        string = NULL;
        free(string);
      } else {
        printf("All Total: %d\n", strlen(string));
      }
    }
    b = c;
  }

  return 0;
}
