#include <stdio.h>
#include <stdlib.h>
#include "misc.h"


size_t nf = 0;
size_t nd = 0;
  
int
ft_print(const char *path,
	 const struct stat *stat,
	 size_t base,
	 size_t level,
	 void *vp) {
  if (S_ISDIR(stat->st_mode))
    nd++;
  else
    nf++;
#if 0
  printf("%s (%s) [level=%d]\n", path, S_ISDIR(stat->st_mode) ? "dir" : "other", level);
#endif
  return 0;
}

int
main(int argc,
     char *argv[]) {
  int i;
  size_t maxlevel = atoi(argv[1]);
  
  for (i = 2; i < argc; i++)
    ft_foreach(argv[i], ft_print, NULL, maxlevel);

  printf("%ld directories & %ld files\n", nd, nf);
  exit(0);
}
