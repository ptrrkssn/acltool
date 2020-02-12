#include <stdio.h>
#include "misc.h"

int
main(int argc,
     char *argv[]) {
  int rc;

  s_trim(argv[1]);
  printf("a1='%s'\n", argv[1]);
  
  rc = s_match(argv[1], argv[2]);
  printf("rc=%d\n", rc);

  return 0;
}
