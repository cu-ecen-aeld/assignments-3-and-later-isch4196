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
#include <pthread.h>
#include "queue.h"

// Network macros
#define SERVER_PORT	"9000"
#define BACKLOG		10	// num pending connections queue to hold
#define FILE_NAME	"/var/tmp/aesdsocketdata"
#define BUF_LENGTH	2

static volatile unsigned char running = 1;

void init_sigaction(void);
void sigint_handler(int sig);
int init_file_writer(void);
void read_file_to_buf(char *buf, unsigned int tot_bytes_recv);
void write_str(int fd, const char *buf, int len);
void close_file(int fd);
void *get_in_addr(struct sockaddr *sa);
void *thread_conn_handler(void *vargp);

/* typedef struct conn_data_s { */
/*     pthread_t *thread; // thread id */
/*     unsigned char thread_done; */
/*     int new_fd; // file descriptor of socket passed into thread */
/*     char *s; // name of socket passed into thread */
/* } conn_data_t; */

typedef struct slist_data_s {
    pthread_t *thread;
    int new_fd; // file descriptor of socket passed into thread
    char *s; // name of socket passed into thread
    unsigned char thread_done;
    SLIST_ENTRY(slist_data_s) entries;
} slist_data_t;

int main(int argc, char *argv[])
{
    init_sigaction();
    
    int server_fd, new_fd;
    socklen_t new_conn_addr_size;
    int opt = 1;
    char s[INET6_ADDRSTRLEN];
    struct addrinfo hints, *servinfo, *p;
    struct sockaddr_storage new_conn_addr;
    unsigned int buf_length = BUF_LENGTH;
    unsigned int tot_bytes_recv = 0;
    int daemon_flag = 0;
    
    if (argc == 2) {
	daemon_flag = !strcmp(argv[1], "-d");
    } 

    // Initializations
    char *buf = (char *)calloc(buf_length, sizeof(char)); // allocate memory for buffer;
    if(!buf) {
	perror("calloc error");
	exit(1);
    }

    int fd = init_file_writer();

    SLIST_HEAD(pthread_slist, slist_data_s) head;
    SLIST_INIT(&head);

    /* slist_data_t *datap = NULL; */
    /* for (int i=0; i<3; i++) { */
    /* 	datap = malloc(sizeof(slist_data_t)); */
    /* 	SLIST_INSERT_HEAD(&head, datap, entries); */
    /* } */
    
    // Set up socket
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
	perror("listen error");
	exit(1);
    }

    if (daemon_flag) {
	pid_t pid = fork();
	if (0 == pid) {
	    // child process
	    goto conn_handle;
	} else if (pid > 0) {
	    exit(0);
	} else {
	    perror("fork error");
	    exit(1);
	}
    }
 conn_handle:
    while(running) {
	new_conn_addr_size = sizeof(new_conn_addr);
	if ((new_fd = accept(server_fd, (struct sockaddr *)&new_conn_addr, &new_conn_addr_size)) == -1) {
	    perror("accept failure");
	    break; // exit gracefully
	}

	// inet_ntop converts IPv4 and IPv6 addresses from binary to text form
	inet_ntop(new_conn_addr.ss_family,
		  get_in_addr((struct sockaddr *)&new_conn_addr),
		  s, sizeof(s));
	
	slist_data_t *datap = (slist_data_t*)malloc(sizeof(slist_data_t));
	datap->thread = (pthread_t*)malloc(sizeof(pthread_t));
	datap->s = (char*)malloc(sizeof(char)*INET6_ADDRSTRLEN);
	strcpy(datap->s, s);
	datap->new_fd = new_fd;
	datap->thread_done = 0;
	
	SLIST_INSERT_HEAD(&head, datap, entries);
	pthread_create(datap->thread, NULL, thread_conn_handler, NULL);
	
	syslog(LOG_INFO, "Accepted connection from %s\n", s);

	// logic for receiving packets
	unsigned int num_bytes_recv = 0;
	unsigned int tot_bytes_packet = 0;
	while(running) {
	    if ((num_bytes_recv = recv(new_fd, buf+tot_bytes_packet, buf_length-tot_bytes_packet-1, 0)) == -1) {
		perror("recv failure");
		exit(1);
	    }
	    if (!num_bytes_recv) break; // connection ended

	    tot_bytes_packet += num_bytes_recv;
	    buf[tot_bytes_packet] = '\0';
	    if (strchr(buf, '\n')) { // check packet done
		break; 
	    }
	    // packet not done, expand buffer if needed
	    if(tot_bytes_packet >= buf_length-1) { 
		if(!(buf = reallocarray(buf, (buf_length <<= 1), sizeof(char)))) {
		    perror("reallocarray error");
		    exit(1);
		}
	    }
	}
	tot_bytes_recv += tot_bytes_packet;
	write_str(fd, buf, tot_bytes_packet);

	// expand buf if contents of file is bigger than it
	if(tot_bytes_recv > buf_length) {
	    do {
		buf_length <<= 1;
	    } while(tot_bytes_recv > buf_length);
	    if(!(buf = reallocarray(buf, (buf_length <<= 1), sizeof(char)))) {
		    perror("reallocarray error");
		    exit(1);
		}
	}
	
	read_file_to_buf(buf, tot_bytes_recv);
	send(new_fd, buf, tot_bytes_recv, 0);

	syslog(LOG_INFO, "Closed connection from %s\n", s);
	pthread_join(*(datap->thread), NULL);
    }
    
    close_file(fd);
    remove(FILE_NAME);
    free(buf);

    slist_data_t *datap = NULL;
    while (!SLIST_EMPTY(&head)) {
	datap = SLIST_FIRST(&head);
	SLIST_REMOVE_HEAD(&head, entries);
	free(datap->thread);
	free(datap->s);
	free(datap);
    }
    
    return 0;
}

void sigint_handler(int sig)
{
    (void)sig;
    syslog(LOG_INFO, "Caught signal, exiting");
    running = 0;
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
    sa.sa_flags = 0; // no flags, just exit if system call interrupted
    if (sigaction(SIGINT, &sa, NULL) < 0) {
	perror("sigaction sigint fail");
	exit(1);
    }
    if (sigaction(SIGTERM, &sa, NULL) < 0) {
	perror("sigaction sigterm fail");
	exit(1);
    }
}

/**
 * init_file_writer()
 *
 * Initialize FILE_NAME to write to
 *
 * Return: void
 */

int init_file_writer(void)
{
    int fd;

    if ((fd = open(FILE_NAME, O_WRONLY|O_CREAT|O_TRUNC, 0644)) < 0) {
	perror("open fali");
	exit(1);
    }
    return fd;
    
}

/**
 * read_file_to_buf()
 *
 * Read contents of FILE_NAME to buf
 *
 * Return: void
 */

void read_file_to_buf(char *buf, unsigned int tot_bytes_recv)
{
    int fd;

    if ((fd = open(FILE_NAME, O_RDONLY, 0644)) < 0) {
	perror("open fali");
	exit(1);
    }

    read(fd, buf, tot_bytes_recv);

    close(fd);
}   

/**
 * write_str() - Write string buf to file fd
 * @fd:  file descriptor of file to write to 
 * @buf: pointer to buffer containing string to write
 * @len: length of string to write
 *
 * Return: void
 */
void write_str(int fd, const char *buf, int len)
{
    if(write(fd, buf, len) < 0) {
	perror("write");
	exit(1);
    }
    
}

/**
 * close_file() - Close a file descriptor
 * @fd: file descriptor to closen
 *
 * Return: void
 */
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

void *thread_conn_handler(void *vargp)
{
    int i = 0;
    i += 2;

    pthread_exit((void*)0);
}
