#include <sys/types.h>
#include <sys/socket.h>
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
#include <signal.h>
#include "dir.h"
#include "usage.h"
#include <ctype.h>

#define PORT "3492"
#define BACKLOG 10

#define MAXDATASIZE 100

void sigchld_handler(int s)
{
    // waitpid() might overwrite errno, so we save and restore it:
    int saved_errno = errno;

    while (waitpid(-1, NULL, WNOHANG) > 0)
        ;

    errno = saved_errno;
}

void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET)
    {
        return &(((struct sockaddr_in *)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6 *)sa)->sin6_addr);
}

int main(int argc, char **argv)
{

    if (argc != 2)
    {
        usage(argv[0]);
        return -1;
    }

    // This is some sample code feel free to delete it
    // This is the main program for the thread version of nc

    int numbytes;
    char buf[MAXDATASIZE];
    int sockfd, new_fd; // listen on sock_fd, new connection on new_fd
    struct addrinfo hints, *servinfo, *p;
    struct sockaddr_storage their_addr; // connector's address information
    socklen_t sin_size;
    struct sigaction sa;
    int yes = 1;
    char s[INET6_ADDRSTRLEN];
    int rv;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE; // use my IP

    if ((rv = getaddrinfo(NULL, argv[1], &hints, &servinfo)) != 0)
    {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }

    for (p = servinfo; p != NULL; p = p->ai_next)
    {
        if ((sockfd = socket(p->ai_family, p->ai_socktype,
                             p->ai_protocol)) == -1)
        {
            perror("server: socket");
            continue;
        }

        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes,
                       sizeof(int)) == -1)
        {
            perror("setsockopt");
            exit(1);
        }

        if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1)
        {
            close(sockfd);
            perror("server: bind");
            continue;
        }

        break;
    }

    freeaddrinfo(servinfo); // all done with this structure

    if (p == NULL)
    {
        fprintf(stderr, "server: failed to bind\n");
        exit(1);
    }

    if (listen(sockfd, BACKLOG) == -1)
    {
        perror("listen");
        exit(1);
    }

    sa.sa_handler = sigchld_handler; // reap all dead processes
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL) == -1)
    {
        perror("sigaction");
        exit(1);
    }
    char *name = (char *)malloc(20);
    printf("server: waiting for connections...\n");

    while (1)
    { // main accept() loop
        sin_size = sizeof their_addr;
        new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
        if (new_fd == -1)
        {
            perror("accept");
            continue;
        }

        inet_ntop(their_addr.ss_family,
                  get_in_addr((struct sockaddr *)&their_addr),
                  s, sizeof s);
        printf("server: got connection from %s\n", s);

        if (!fork())
        {                  // this is the child process
            close(sockfd); // child doesn't need the listener
            //Loop here until QUIT
            if (send(new_fd, "220, Service ready for new user.\n", 34, 0) == -1)
                perror("send");
            while (1)
            {

                if ((numbytes = recv(new_fd, buf, MAXDATASIZE - 1, 0)) == -1)
                {
                    perror("recv");
                    exit(1);
                }
                buf[numbytes] = '\0';
                printf("server: received %s", buf);
                if (strncmp(buf, "QUIT", 4) == 0)
                {
                    printf("next connection\n");
                    break;
                }
                else if (strncmp(buf, "USER cs317", 10) == 0)
                {
                    if (send(new_fd, "230 Login successful.\n", 23, 0) == -1)
                        perror("send");
                    while (1)
                    {
                        if ((numbytes = recv(new_fd, buf, MAXDATASIZE - 1, 0)) == -1)
                        {
                            perror("recv");
                            exit(1);
                        }
                        else
                        {

                            buf[numbytes] = '\0';
                            printf("server: received %s", buf);
                            if (strncmp(buf, "CWD", 3) == 0)
                            {
                                printf("Here \n");
                                char *path = (char *)malloc(strlen(buf));
                                ;
                                strcpy(path, &buf[4]);
                                printf("moving to directory: %s", path);
                                chdir(path);
                            }
                            if (strncmp(buf, "CDUP", 4) == 0)
                            {
                                char *cwd;
                                char buff[256 + 1];
                                cwd = getcwd(buff, 256 + 1);
                                if (cwd != NULL)
                                {
                                    printf("My working directory is %s.\n", cwd);
                                }
                            }
                            if (strncmp(buf, "TYPE", 4) == 0)
                            {
                            }
                            if (strncmp(buf, "MODE", 4) == 0)
                            {
                            }
                            if (strncmp(buf, "STRU", 4) == 0)
                            {
                            }
                            if (strncmp(buf, "RETR", 4) == 0)
                            {
                            }
                            if (strncmp(buf, "PASV", 4) == 0)
                            {
                            }
                            if (strncmp(buf, "NLST", 4) == 0)
                            {
                            }
                            if (strncmp(buf, "QUIT", 4) == 0)
                            {
                                printf("next connection\n");
                                exit(0);
                            }
                        }
                    }
                }
                else
                {
                    if (send(new_fd, "530 Please login with USER\n", 37, 0) == -1)
                        perror("send");
                }
            }
            close(new_fd);
            exit(0);
        }
        close(new_fd);

        // parent doesn't need this
    }

    return 0;
}
// Check the command line arguments

// This is how to call the function in dir.c to get a listing of a directory.
// It requires a file descriptor, so in your code you would pass in the file descriptor
// returned for the ftp server's data connection

//printf("Printed %d directory entries\n", listFiles(1, "."));
