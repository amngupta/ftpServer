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

typedef struct Command
{
    char command[5];
    char arg[128];
} Command;

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

void parse_command(char *cmdstring, Command *cmd)
{
    sscanf(cmdstring, "%s %s", cmd->command, cmd->arg);
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
    char cwd[1024];
   
    char buf[MAXDATASIZE];
    int sockfd, new_fd; // listen on sock_fd, new connection on new_fd
    struct addrinfo hints, *servinfo, *p;
    struct sockaddr_storage their_addr; // connector's address information
    socklen_t sin_size;
    struct sigaction sa;
    int yes = 1;
    char s[INET6_ADDRSTRLEN];
    int rv;

    void sendResponse(char *status)
    {
        if (send(new_fd, status, strlen(status), 0) == -1)
            perror("send");
    }

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
            sendResponse("220, Service ready for new user.\n");
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
                    sendResponse("230 Login successful.\n");
                    while (1)
                    {
                        Command *cmd = malloc(sizeof(Command));
                        if ((numbytes = recv(new_fd, buf, MAXDATASIZE - 1, 0)) == -1)
                        {
                            perror("recv");
                            exit(1);
                        }
                        else
                        {

                            buf[numbytes] = '\0';
                            printf("server: received %s", buf);
                            parse_command(buf, cmd);
                            if (strncmp(cmd->command, "SYST", 4) == 0)
                            {
                                sendResponse("215 UNIX \n");
                            }
                            if (strncmp(cmd->command, "FEAT", 4) == 0)
                            {
                                sendResponse("211\n");
                            }
                            if (strncmp(cmd->command, "PWD", 3) == 0)
                            {
                                sendResponse("212\n");
                            }
                            if (strncmp(cmd->command, "CWD", 3) == 0)
                            {
                                if (chdir(cmd->arg) == 0)
                                {
                                    sendResponse("250 Directory successfully changed.\n");
                                    // if (send(new_fd, "250 Directory successfully changed.\n", 37, 0) == -1)
                                    //     perror("send");
                                }
                                else
                                {
                                    sendResponse("550 Failed to change directory.\n");
                                }
                            }
                            if (strncmp(cmd->command, "CDUP", 4) == 0)
                            {
                                if (chdir("..") == 0)
                                {
                                    sendResponse("250 Directory successfully changed.\n");
                                }
                                else
                                {
                                    sendResponse("550 Failed to change directory.\n");
                                }
                            }
                            if (strncmp(cmd->command, "TYPE", 4) == 0)
                            {
                                if (cmd->arg[0] == 'I')
                                {
                                    sendResponse("200 Switching to Binary mode.\n");
                                }
                                else if (cmd->arg[0] == 'A')
                                {
                                    /* Type A must be always accepted according to RFC */
                                    sendResponse("200 Switching to ASCII mode.\n");
                                }
                                else
                                {
                                    sendResponse("504 Command not implemented for that parameter.\n");
                                }
                            }
                            if (strncmp(cmd->command, "MODE", 4) == 0)
                            {
                                if (cmd->arg[0] == 'C') 
                                {
                                    sendResponse("220 Mode set to C\n");
                                }
                                else if (cmd->arg[0] == 'B')
                                {
                                    sendResponse("220 Mode set to B\n");
                                }
                                else if (cmd->arg[0] == 'S')
                                {
                                    sendResponse("220 Mode set to S\n");
                                }
                                else 
                                {
                                   sendResponse("504 Bad MODE command\n"); 
                                }
                                
                            }
                            if (strncmp(cmd->command, "STRU", 4) == 0)
                            {
                            }
                            if (strncmp(cmd->command, "RETR", 4) == 0)
                            {
                            }
                            if (strncmp(cmd->command, "PASV", 4) == 0)
                            {
                            }
                            if (strncmp(cmd->command, "NLST", 4) == 0)
                            {
                                if (getcwd(cwd, sizeof(cwd)) != NULL)
                                {
                                    listFiles(new_fd, cwd);
                                }
                                else
                                {
                                    perror("getcwd() error");
                                }
                            }
                            if (strncmp(cmd->command, "QUIT", 4) == 0)
                            {
                                printf("next connection\n");
                                exit(0);
                            }     
                        }
                    }
                }
                else
                {
                    sendResponse("530 Please login with USER\n");
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
