#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>

int main(void) {
  int fd = open("/dev/lunix0-batt", O_RDONLY);
  size_t pagesize = getpagesize();
  char * region = mmap(
    (void*) (pagesize * (1 << 20)), pagesize,
    PROT_READ, MAP_FILE|MAP_PRIVATE,
    fd, 0
  );
  // fwrite(region, 1, pagesize, stdout);
  int i;
  for (i=0; i<pagesize; i++)
    putchar(region[i]);
  int unmap_result = munmap(region, pagesize);
  close(fd);
  return 0;
}