#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <syslog.h>
#include <signal.h>
#include <sys/stat.h>
#include <fcntl.h>

// Network macros
#define SERVER_PORT	"9000"
#define BACKLOG		10	// num pending connections queue to hold
#define BUF_LENGTH      1048576
#define FILE_NAME	"/var/tmp/aesdsocketdata"

static volatile unsigned char running = 1;

void init_sigaction(void);
void sigint_handler(int sig);

int init_file(void);
void write_str(int fd, const char *buf, int len);
void close_file(int fd);

void *get_in_addr(struct sockaddr *sa);

int main(int argc, char *argv[])
{
    int fd = init_file();
    init_sigaction();
    
    int server_fd, new_fd;
    socklen_t new_conn_addr_size;
    char *buf;
    int opt = 1;
    int num_bytes = 0;
    char s[INET6_ADDRSTRLEN];
    struct addrinfo hints, *servinfo, *p;
    struct sockaddr_storage new_conn_addr;

    // hints points to an addrinfo structure that specifies criteria for
    // selecting socket address structure returned in res in getaddrinfo function
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; // don't care IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM; // TCP stream sockets
    hints.ai_flags = AI_PASSIVE; // fill in my IP for me

    // identify an internet host and a service, and return one of more addrinfo structures
    if ((getaddrinfo(NULL, SERVER_PORT, &hints, &servinfo)) != 0) {
	perror("getaddrinfo failed");
	exit(EXIT_FAILURE);
    }

    // loop through all the results from getaddrinfo and bind to first one
    for(p = servinfo; p != NULL; p = p->ai_next) {
	if ((server_fd = socket(p->ai_family, p->ai_socktype, // create endpt for communication
				p->ai_protocol)) == -1) {
	    perror("server: socket");
	    continue;
	}

	if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt,
		       sizeof(int)) == -1) {
	    perror("setsockopt");
	    exit(1);
	}

	if (bind(server_fd, p->ai_addr, p->ai_addrlen) == -1) { // bind addr to socket
	    close(server_fd);
	    perror("server: bind");
	    continue;
	}

	break;
    }

    freeaddrinfo(servinfo); // all done with this structure

    // make sure we were able to bind to something
    if (!p) {
	perror("server: failed to bind");
	exit(1);
    }

    // mark socket as a passive socket (accepts connections)
    if (listen(server_fd, BACKLOG) == -1) { 
	perror("listen");
	exit(1);
    }

    unsigned int temp = 0;
    
    buf = (char *)calloc(BUF_LENGTH, sizeof(char)); // allocate memory for buffer
    while(running) {
	new_conn_addr_size = sizeof(new_conn_addr);
	new_fd = accept(server_fd, (struct sockaddr *)&new_conn_addr, &new_conn_addr_size);

	// inet_ntop converts IPv4 and IPv6 addresses from binary to text form
	inet_ntop(new_conn_addr.ss_family,
		  get_in_addr((struct sockaddr *)&new_conn_addr),
		  s, sizeof(s));
	syslog(LOG_INFO, "Accepted connection from %s\n", s);

	// logic for receiving a message
	/* unsigned int idx = 0; */
	/* unsigned char mult_size = 1; */
	
	while(running) {
#warning is better to make recv nonblocking in case user exits right after starting program.
	    if ((num_bytes = recv(new_fd, buf+temp, BUF_LENGTH-temp-1, 0)) == -1) {
		perror("recv failure");
		exit(1);
	    }
	    if(!num_bytes) { // 0 bytes mean connection ended for TCP stream
		break;
	    }
	    temp += num_bytes;
	    buf[temp] = '\0';
	    printf("Received: %s", buf);
 	    write_str(fd, buf, temp);
	    send(new_fd, buf, temp, 0);
	}
	/* while(1) { */
	/*     if ((num_bytes = recv(new_fd, buf+idx, (BUF_LENGTH*mult_size)-idx-1, 0)) == -1) { */
	/* 	perror("recv failure"); */
	/* 	exit(1); */
	/*     } */
	/*     buf[num_bytes+idx] = '\0'; // so strchr knows where to end search */
	/*     idx += num_bytes; */
	/*     if (!strchr(buf, '\n')) { */
	/* 	mult_size += 1; */
		
	/* 	buf = (char *)realloc(buf, BUF_LENGTH*sizeof(char)*mult_size); */
	/*     } else { */
	/* 	write_str(fd, buf, idx); */
	/* 	send(new_fd, buf, idx, 0); */
	/* 	idx = 0; */
	/*     } */
	/* } */
	
	syslog(LOG_INFO, "Closed connection from %s\n", s);
    }
    
    close_file(fd);
    free(buf);
    return 0;
}

void sigint_handler(int sig)
{
    (void)sig;
    syslog(LOG_INFO, "Caught signal, exiting");
    running = 0;
    printf("running: %d\n", running);
}

/**
 * init_sigaction() - Initialize sigaction for SIGINT, SIGTERM signals
 *
 * Return: void
 */
void init_sigaction(void)
{
    struct sigaction sa;
    sa.sa_handler = sigint_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART; // if a blocked call to one of interfaces is interrupted by signal handler, then call is automatically restarted, such as the function accept()
    if (sigaction(SIGINT, &sa, NULL) < 0) {
	perror("sigaction fail");
	exit(1);
    }
    if (sigaction(SIGTERM, &sa, NULL) < 0) {
	perror("sigaction fail");
	exit(1);
    }
}

/**
 * init_file()
 *
 * Initialize FILE_NAME to write to
 *
 * Return: void
 */

int init_file(void)
{
    int fd;

    fd = open(FILE_NAME, O_WRONLY|O_CREAT|O_TRUNC, 0644);
    if (fd < 0) {
	perror("open fali");
	exit(1);
    }
    /* if (fd < 0) { */
    /* 	if (errno == EEXIST) { */
    /* 	    if (truncate(FILE_NAME, 0) < 0) { */
    /* 		perror("truncate fail"); */
    /* 		exit(1); */
    /* 	    } */
    /* 	} else { */
    /* 	    perror("open fail"); */
    /* 	    exit(1); */
    /* 	} */
    /* } */

    return fd;
    
}   

void write_str(int fd, const char *buf, int len)
{
    if(write(fd, buf, len) < 0) {
	perror("write");
	exit(1);
    }
    
}

void close_file(int fd)
{
    if(close(fd) < 0) {
	perror("close");
	exit(1);
    }
}

// get sockaddr, IPV4 or IPV6
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}
