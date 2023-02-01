#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>
#include <fcntl.h>
#include <unistd.h>

#define DEBUG	1
#define ARGS	((2)+1)

int main(int argc, char *argv[])
{
  if(argc != ARGS) {
    printf("Usage: %s file_name str_to_write\n", argv[0]);
    exit(1);
  }

  openlog(NULL, LOG_CONS, LOG_USER);
  
  const char* file_name= argv[1];
  const char* str_to_write= argv[2];

  int fd = creat(file_name, S_IRUSR|S_IWUSR);
  if(fd == -1) {
    syslog(LOG_ERR, "%s", "Error creating file");
    exit(1);
  }
  
  write(fd, str_to_write, strlen(str_to_write));
  syslog(LOG_DEBUG, "Writing %s to %s", str_to_write, file_name);

  closelog();
  if(close(fd) == -1) {
    syslog(LOG_ERR, "%s", "Error closing file");
  }
  
  return 0;
}
