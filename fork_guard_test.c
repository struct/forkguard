/* Copyright Chris Rohlf - 2017 */

#include <dlfcn.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>

#define OK 0
#define ERROR -1

/* Do things child processes do ... */
int32_t child_process_stuff() {
	fprintf(stdout, "Attempting connect(localhost:80)\n");
	int sockfd;
    struct sockaddr_in servaddr;
    struct hostent *server;

printf("000\n");
    sockfd = socket(AF_INET, SOCK_STREAM, 0);

printf("222\n");
    if(sockfd < 0) {
        fprintf(stdout, "Could not open socket\n");
    }
printf("111\n");
    server = gethostbyname("localhost");

printf("333\n");
    if(server == NULL) {
        fprintf(stdout, "No such host\n");
        exit(0);
    }

    memset((char *) &servaddr, 0x0, sizeof(servaddr));    
    memcpy((char *)server->h_addr,  (char *)&servaddr.sin_addr.s_addr, server->h_length);
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(80);
fprintf(stdout, "connected?\n");
    if(connect(sockfd, (struct sockaddr *) &servaddr,sizeof(servaddr)) < 0) {
        fprintf(stdout, "Could not connect\n");
	}

    fprintf(stdout, "Closing the socket...\n");
	close(sockfd);

	return OK;
}

int main(int argc, char *argv[]) {
	fprintf(stdout, "Parent pid is %d\n", getpid());
	pid_t child_pid;
	int32_t status = 0;

    fprintf(stdout, "Forking child now\n");

    while(1) {
    	if((child_pid = fork()) == 0) {
            fprintf(stdout, "Child PID is %d\n", getpid());
            child_process_stuff();
            exit(0);
    	}

        waitpid(child_pid, &status, 0);
    }

	return OK;
}
