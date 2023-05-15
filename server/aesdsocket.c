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
#include <time.h>
#include <semaphore.h>
#include "queue.h"

// Network macros
#define SERVER_PORT	"9000"
#define BACKLOG		10	// num pending connections queue to hold
#define FILE_NAME	"/var/tmp/aesdsocketdata"
#define BUF_LENGTH	1024

#define SECS_IN_DAY	(24 * 60 * 60)
#define TIME_EXPIRE     10	// seconds

void init_sigaction(void);
void sigint_handler(int sig);
int init_file_writer(void);
void read_file_to_buf(char *buf);
void write_str(const char *buf, int len);
void close_file(int fd);
void *get_in_addr(struct sockaddr *sa);
void *thread_conn_handler(void *vargp);
void *ts_handler(void *vargp);
void release_ts(int id);
    
typedef struct conn_data_s {
    int new_fd; // file descriptor of socket passed into thread
    char *s; // name of socket passed into thread
    unsigned char thread_done;
} conn_data_t;

typedef struct slist_data_s {
    pthread_t *thread;
    conn_data_t conn_data;
    SLIST_ENTRY(slist_data_s) entries;
} slist_data_t;

static int fd;
static unsigned int tot_bytes_recv = 0;
static volatile unsigned char running = 1;
static pthread_mutex_t mut = PTHREAD_MUTEX_INITIALIZER;
static sem_t sem_ts;
static timer_t timer_ts;
static struct itimerspec itime = {{TIME_EXPIRE,0}, {TIME_EXPIRE,0}};

int main(int argc, char *argv[])
{
    /* timer_t timerid = NULL; */
    /* struct sigevent sev; */
    /* timer_create(CLOCK_REALTIME, &sev, &timerid); */
    
    // we can use timer_create. Timers are not inherited, so create in child
    /* struct timespec res; */
    /* if (clock_gettime(CLOCK_REALTIME, &res) == -1) { */
    /* 	perror("clock_getres"); */
    /* 	exit(EXIT_FAILURE); */
    /* } */
    /* long days = res.tv_sec / SECS_IN_DAY; */
    /* if (days > 0) */
    /* 	printf("%ld days + ", days); */
    /* unsigned int year = 1970 + days / 365; */
    /* printf("%2dy %2dh %2dm %2ds\n", */
    /* 	   (int) year, */
    /* 	   (int) (res.tv_sec % SECS_IN_DAY) / 3600, */
    /* 	   (int) (res.tv_sec % 3600) / 60, */
    /* 	   (int) res.tv_sec % 60); */

    /* time_t t = time(NULL); */
    /* struct tm tm = *localtime(&t); */
    /* printf("now: %d-%02d-%02d %02d:%02d:%02d\n", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec); */

    /* return 0; */
    
    pthread_mutex_init(&mut, NULL);
    
    init_sigaction();
    
    int server_fd, new_fd;
    int opt = 1;
    socklen_t new_conn_addr_size;
    struct addrinfo hints, *servinfo, *p;
    struct sockaddr_storage new_conn_addr;
    unsigned char daemon_flag = 0;
    
    if (argc == 2) {
	daemon_flag = !strcmp(argv[1], "-d");
    } 

    fd = init_file_writer();

    SLIST_HEAD(pthread_slist, slist_data_s) head;
    SLIST_INIT(&head);

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

    freeaddrinfo(servinfo); // all done with this structure, discard

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
	    exit(0); // parent process
	} else {
	    perror("fork error");
	    exit(1);
	}
    }
 conn_handle:
    // create a thread to append timestamp to file every 10 sec
    if (sem_init(&sem_ts, 0, 0)) {
	perror("sem_init");
	exit(EXIT_FAILURE);
    }
    pthread_t *ts_thread = (pthread_t*)malloc(sizeof(pthread_t)); // time stamp thread
    pthread_create(ts_thread, NULL, ts_handler, NULL);

    int flags = 0;
    timer_create(CLOCK_REALTIME, NULL, &timer_ts);
    signal(SIGALRM, (void(*)()) release_ts);
    itime.it_interval.tv_sec = TIME_EXPIRE;
    itime.it_interval.tv_nsec = 0;
    itime.it_value.tv_sec = TIME_EXPIRE;
    itime.it_value.tv_nsec = 0;
    timer_settime(timer_ts, flags, &itime, NULL);
    
    // waits for a connection and creates a new thread to handle
    while(running) {
	new_conn_addr_size = sizeof(new_conn_addr);
	if ((new_fd = accept(server_fd, (struct sockaddr *)&new_conn_addr, &new_conn_addr_size)) == -1) {
	    perror("accept failure");
	    break; // exit gracefully
	}

	// initialize node data
	slist_data_t *datap = (slist_data_t*)malloc(sizeof(slist_data_t));
	datap->thread = (pthread_t*)malloc(sizeof(pthread_t));
	datap->conn_data.s = (char*)malloc(sizeof(char)*INET6_ADDRSTRLEN);
	datap->conn_data.new_fd = new_fd;
	datap->conn_data.thread_done = 0;
	
	// inet_ntop converts IPv4 and IPv6 addresses from binary to text form
	inet_ntop(new_conn_addr.ss_family,
		  get_in_addr((struct sockaddr *)&new_conn_addr),
		  datap->conn_data.s, sizeof(char)*INET6_ADDRSTRLEN);
	
	SLIST_INSERT_HEAD(&head, datap, entries);
	pthread_create(datap->thread, NULL, thread_conn_handler, (void*)&(datap->conn_data));

	// join threads and delete their data if they have finished
	slist_data_t *tdatap = NULL;
	SLIST_FOREACH_SAFE(datap, &head, entries, tdatap) {
	    if (datap->conn_data.thread_done) {
		pthread_join(*(datap->thread), NULL);
		SLIST_REMOVE(&head, datap, slist_data_s, entries);
		free(datap->thread);
		free(datap->conn_data.s);
		free(datap);
	    }
	}
    }

    // clean up after received a sigint
    close_file(fd);
    remove(FILE_NAME);
    pthread_mutex_destroy(&mut);
    slist_data_t *datap = NULL;
    slist_data_t *tdatap = NULL;
    SLIST_FOREACH_SAFE(datap, &head, entries, tdatap) {
	if (datap->conn_data.thread_done) {
	    pthread_join(*(datap->thread), NULL); // wait for threads to finish on sigint? else memleak
	    SLIST_REMOVE(&head, datap, slist_data_s, entries);
	    free(datap->thread);
	    free(datap->conn_data.s);
	    free(datap);
	}
    }
    // clean up data involving timestamp generator
    sem_post(&sem_ts);
    pthread_join(*ts_thread, NULL);
    free(ts_thread);
    sem_close(&sem_ts);
    
    return 0;
}

/**
 * sigint_handler() - Notify program to shut down on sigint
 *
 * Return: void
 */
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
 * Note that the superior option is to use a pthread_rwlock to allow multiple readers while only one writer
 * But, this is good enough too :)
 *
 * Return: void
 */
void read_file_to_buf(char *buf)
{
    int fd;

    if ((fd = open(FILE_NAME, O_RDONLY, 0644)) < 0) {
	perror("open fail");
	exit(1);
    }
    pthread_mutex_lock(&mut);
    read(fd, buf, tot_bytes_recv);
    pthread_mutex_unlock(&mut);
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
void write_str(const char *buf, int len)
{
    pthread_mutex_lock(&mut);
    tot_bytes_recv += len; // put here instead of outside func in case of read right after tot_bytes_recv is increased
    if(write(fd, buf, len) < 0) {
	perror("write");
	//exit(1); // don't exit immediately to allow clean-up from sigint
    }
    pthread_mutex_unlock(&mut);
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

/**
 * thread_conn_handler() - Handles receiving/sending data from/to a client
 * @vargp: argument into thread, containing connection data
 *
 * Return: void
 */
void *thread_conn_handler(void *vargp)
{
    conn_data_t *conn_data = (conn_data_t*)vargp;
    syslog(LOG_INFO, "Accepted connection from %s\n", conn_data->s);

    unsigned int buf_length = BUF_LENGTH;
    char *buf = (char *)calloc(buf_length, sizeof(char)); // allocate memory for buffer;
    if(!buf) {
	perror("calloc error");
	exit(1);
    }
    unsigned int num_bytes_recv = 0;
    unsigned int tot_bytes_packet = 0; // total bytes received so far in packet

    // Obtain all of the data
    while(running) {
	if ((num_bytes_recv = recv(conn_data->new_fd, buf+tot_bytes_packet, buf_length-tot_bytes_packet-1, 0)) == -1) {
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
    
    //tot_bytes_recv += tot_bytes_packet;
    write_str(buf, tot_bytes_packet);

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
	
    read_file_to_buf(buf);
    send(conn_data->new_fd, buf, tot_bytes_recv, 0);    
    free(buf);
    
    syslog(LOG_INFO, "Closed connection from %s\n", conn_data->s);
    conn_data->thread_done = 1;
    pthread_exit((void*)0);
}

/**
 * ts_handler() - Handler called periodically to generate a timestamp and write to file
 *
 * Return: void
 */
void *ts_handler(void *vargp)
{
    while(running) {
	sem_wait(&sem_ts);

	// generate timestamp
	char outstr[100];
	time_t t;
	struct tm *tmp;

	t = time(NULL);
	tmp = localtime(&t);
	if (tmp == NULL) {
	    perror("localtime");
	    exit(EXIT_FAILURE);
	}
    
	char ex[] = "timestamp: %a, %d %b %Y %T %z\n";
	if (strftime(outstr, sizeof(outstr), ex, tmp) == 0) {
	    fprintf(stderr, "strftime returned 0");
	    exit(EXIT_FAILURE);
	}
	write_str(outstr, strlen(outstr));
    }
    pthread_exit((void*)0);
}

/**
 * release_ts() - Post a semaphore to allow ts_handler logic to run
 * 
 * Return: void
 */
void release_ts(int id)
{
    sem_post(&sem_ts);
}
