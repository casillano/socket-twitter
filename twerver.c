#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <signal.h>
#include "socket.h"

#ifndef PORT
#define PORT 58111
#endif

#define LISTEN_SIZE 5
#define WELCOME_MSG "Welcome to CSC209 Twitter! Enter your username:\r\n"
#define SEND_MSG "send"
#define SHOW_MSG "show"
#define FOLLOW_MSG "follow"
#define UNFOLLOW_MSG "unfollow"
#define BUF_SIZE 256
#define MSG_LIMIT 8
#define FOLLOW_LIMIT 5

struct client
{
    int fd;
    struct in_addr ipaddr;
    char username[BUF_SIZE];
    char message[MSG_LIMIT][BUF_SIZE];
    struct client *following[FOLLOW_LIMIT]; // Clients this user is following
    struct client *followers[FOLLOW_LIMIT]; // Clients who follow this user
    char inbuf[BUF_SIZE];                   // Used to hold input from the client
    char *in_ptr;                           // A pointer into inbuf to help with partial reads
    struct client *next;
};

// Provided functions.
void add_client(struct client **clients, int fd, struct in_addr addr);
void remove_client(struct client **clients, int fd);

void announce(struct client **active_clients, char *s);
void announce_disconnect(struct client **active_clients_ptr, char *username, int fd);

void write_wrapper(struct client *user, char *message, struct client **clients_ptr, int is_active)
{
    // Write to the user, and disconnect the user if the write fails.
    if (write(user->fd, message, strlen(message)) == -1)
    {
        fprintf(stderr,
                "Write to client %s failed\n", inet_ntoa(user->ipaddr));

        // If the user is an active client, announce his disconnection to all active users.
        if (is_active)
        {
            announce_disconnect(clients_ptr, user->username, user->fd);
        }
        else
        {
            remove_client(clients_ptr, user->fd);
        }
    }
}

// Move client c from new_clients list to active_clients list.
void activate_client(struct client *c,
                     struct client **active_clients_ptr, struct client **new_clients_ptr)
{

    // Remove the client from the new_clients linked list.
    if ((*new_clients_ptr)->fd == c->fd)
    {
        *new_clients_ptr = (*new_clients_ptr)->next;
    }
    else
    {
        struct client **p;
        for (p = new_clients_ptr; *p && (*p)->next && (*p)->next->fd != c->fd; p = &(*p)->next)
            ;

        (*p)->next = c->next;
    }

    // Add the client to the head of the active_clients linked list.
    if (*active_clients_ptr == NULL)
    {
        *active_clients_ptr = c;
        c->next = NULL;
    }
    else
    {
        c->next = *active_clients_ptr;
        *active_clients_ptr = c;
    }

    char message[BUF_SIZE];
    strcpy(message, c->username);
    strcat(message, " has just joined.");
    announce(active_clients_ptr, message);
}

// The set of socket descriptors for select to monitor.
// This is a global variable because we need to remove socket descriptors
// from allset when a write to a socket fails.
fd_set allset;

// Send the message in s to all followers of curr_client
void send_to_followers(struct client *curr_client, char *s, struct client **active_clients_ptr)
{

    int space_for_message = 0;
    int index;
    // Check if the user has already sent MSG_LIMIT messages.
    for (int i = 0; i < MSG_LIMIT; i++)
    {
        if (curr_client->message[i][0] == '\0')
        {
            space_for_message = 1;
            index = i;
            break;
        }
    }
    if (space_for_message)
    {
        // Add the message to curr_clients message array.
        strcpy(curr_client->message[index], s);
        curr_client->message[index][strlen(curr_client->message[index])] = '\0';

        char new_message[BUF_SIZE];
        strcpy(new_message, curr_client->username);
        strcat(new_message, ": ");
        strcat(new_message, s);
        strcat(new_message, "\r\n");
        // Write the message to all of curr_client's followers.
        for (int i = 0; i < FOLLOW_LIMIT; i++)
        {
            if (curr_client->followers[i] != NULL)
            {
                write_wrapper(curr_client->followers[i], new_message, active_clients_ptr, 1);
            }
        }
        printf("%s just sent a message.\n", curr_client->username);
    }
    else
    {
        char error_message[BUF_SIZE] = "You have already sent the maximum number of messages.\r\n";
        write_wrapper(curr_client, error_message, active_clients_ptr, 1);
    }
}

// Find and return the active user whose username matches the string s.
struct client *get_client_struct_from_username(struct client **active_clients_ptr, char *s)
{
    struct client **p;
    for (p = active_clients_ptr; *p && (strcmp((*p)->username, s) != 0); p = &(*p)->next)
        ;

    if (*p && (strcmp((*p)->username, s) == 0))
    {
        return *p;
    }
    // Client with the given username does not exist in active clients.
    return NULL;
}

void unfollow_user(struct client *user, struct client **active_clients_ptr, char *username_to_follow)
{
    // Find the pointer to the client with the given username.
    struct client *client_to_unfollow = get_client_struct_from_username(active_clients_ptr, username_to_follow);
    if (client_to_unfollow == NULL)
    {
        char unfollow_error_msg[BUF_SIZE] = "Error: Username does not exist.\r\n";
        write_wrapper(user, unfollow_error_msg, active_clients_ptr, 1);
    }
    else
    {
        int index1 = -1;
        int index2 = -1;
        // Find the index in the user's following array where the user to unfollow is stored.
        for (int i = 0; i < FOLLOW_LIMIT; i++)
        {
            if (user->following[i] != NULL)
            {
                if ((user->following[i])->fd == client_to_unfollow->fd)
                {
                    index1 = i;
                }
            }
            // Find the index in the followers array of the user to be unfollowed.
            if (client_to_unfollow->followers[i] != NULL)
            {
                if ((client_to_unfollow->followers[i])->fd == user->fd)
                {
                    index2 = i;
                }
            }
        }

        // If the user is not following the user to be unfollowed, send error.
        if (index1 == -1 || index2 == -1)
        {
            char unfollow_error_msg[BUF_SIZE] = "Error: You are not following anyone with the given username\r\n";
            write_wrapper(user, unfollow_error_msg, active_clients_ptr, 1);
        }
        else
        {
            user->following[index1] = NULL;
            client_to_unfollow->followers[index2] = NULL;
            printf("%s has unfollowed %s\n", user->username, client_to_unfollow->username);
            printf("%s no longer has %s as a follower\n", client_to_unfollow->username, user->username);
        }
    }
}

// Send the message in s to all clients in active_clients.
void announce(struct client **active_clients, char s[BUF_SIZE])
{
    struct client **p;
    strcat(s, "\r\n");
    for (p = active_clients; *p != NULL; p = &(*p)->next)
    {
        write_wrapper(*p, s, active_clients, 1);
    }
}

/* 
 * Create a new client, initialize it, and add it to the head of the linked
 * list.
 */
void add_client(struct client **clients, int fd, struct in_addr addr)
{
    struct client *p = malloc(sizeof(struct client));
    if (!p)
    {
        perror("malloc");
        exit(1);
    }

    printf("Adding client %s\n", inet_ntoa(addr));
    p->fd = fd;
    p->ipaddr = addr;
    p->username[0] = '\0';
    p->in_ptr = p->inbuf;
    p->inbuf[0] = '\0';
    p->next = *clients;
    for (int i = 0; i < FOLLOW_LIMIT; i++)
    {
        p->followers[i] = NULL;
        p->following[i] = NULL;
    }

    // initialize messages to empty strings
    for (int i = 0; i < MSG_LIMIT; i++)
    {
        p->message[i][0] = '\0';
    }

    *clients = p;
}

/*
 * Remove the client with the given fd from the given
 * follower/follwing list old_arr.
 */
void remove_client_from_array(int fd, struct client **old_arr)
{
    for (int i = 0; i < FOLLOW_LIMIT; i++)
    {
        if (old_arr[i] != NULL && old_arr[i]->fd == fd)
        {
            old_arr[i] = NULL;
        }
    }
}

/* 
 * Remove client from the linked list and close its socket.
 * Also, remove socket descriptor from allset.
 */
void remove_client(struct client **clients, int fd)
{
    struct client **p;

    for (p = clients; *p && (*p)->fd != fd; p = &(*p)->next)
        ;

    // Now, p points to (1) top, or (2) a pointer to another client
    // This avoids a special case for removing the head of the list
    if (*p)
    {
        // Remove the client from other clients' following/followers
        // lists
        for (int i = 0; i < FOLLOW_LIMIT; i++)
        {
            if ((*p)->followers[i] != NULL)
            {
                remove_client_from_array((*p)->fd, (*p)->followers[i]->following);
            }
            if ((*p)->following[i] != NULL)
            {
                remove_client_from_array((*p)->fd, (*p)->following[i]->followers);
            }
        }

        // Remove the client
        struct client *t = (*p)->next;
        printf("Removing client %d %s\n", fd, inet_ntoa((*p)->ipaddr));
        FD_CLR((*p)->fd, &allset);
        close((*p)->fd);
        free(*p);
        *p = t;
    }
    else
    {
        fprintf(stderr,
                "Trying to remove fd %d, but I don't know about it\n", fd);
    }
}

// Send a message to all active users when an active user has disconnected.
void announce_disconnect(struct client **active_clients_ptr, char *username, int fd)
{
    char message[BUF_SIZE] = "Goodbye ";
    strcat(message, username);
    remove_client(active_clients_ptr, fd);
    announce(active_clients_ptr, message);
}

// Follow the user with the given username, if it exists.
void follow_user(struct client *user, struct client **active_clients_ptr, char *username_to_follow)
{
    int space_to_follow = 0;
    int space_to_be_followed = 0;
    int index1, index2;
    char *follow_error_msg;

    // Find the pointer of the client to be followed with the given username.
    struct client *client_to_follow = get_client_struct_from_username(active_clients_ptr, username_to_follow);

    // Check if the user is trying to follow him/herself.
    if (strcmp(user->username, username_to_follow) == 0)
    {
        follow_error_msg = "Error: You cannot follow yourself.\r\n";
        write_wrapper(user, follow_error_msg, active_clients_ptr, 1);
    }
    else if (client_to_follow == NULL)
    {
        follow_error_msg = "Error: Username does not exist.\r\n";
        write_wrapper(user, follow_error_msg, active_clients_ptr, 1);
    }
    else
    {
        int already_following = 0;
        // Check if the user is already following client_to_follow.
        for (int i = 0; i < FOLLOW_LIMIT; i++)
        {
            if (user->following[i] != NULL)
            {
                if (user->following[i]->fd == client_to_follow->fd)
                {
                    already_following = 1;
                    follow_error_msg = "You are already following this user.\r\n";
                    write_wrapper(user, follow_error_msg, active_clients_ptr, 1);
                    break;
                }
            }
        }
        if (!already_following)
        {
            // Check that the user does not follow FOLLOW_LIMIT users
            // and the user with the username username_to_follow does
            // not have FOLLOW_LIMIT followers.
            for (int i = 0; i < FOLLOW_LIMIT; i++)
            {
                if (!space_to_be_followed && client_to_follow->followers[i] == NULL)
                {
                    space_to_be_followed = 1;
                    index1 = i;
                }
                if (!space_to_follow && user->following[i] == NULL)
                {
                    space_to_follow = 1;
                    index2 = i;
                }
            }
            if (space_to_be_followed && space_to_follow)
            {
                // Update the user's following list and client_to_follow's follower list.
                client_to_follow->followers[index1] = user;
                user->following[index2] = client_to_follow;
                printf("%s is following %s\n", user->username, client_to_follow->username);
                printf("%s has %s as a follower\n", client_to_follow->username, user->username);
            }
            else
            {
                if (!space_to_be_followed)
                {
                    follow_error_msg = "Error: this user has the maximum number of followers.\r\n";
                }
                else
                {
                    follow_error_msg = "Error: you have already followed the maximum number of users.\r\n";
                }
                write_wrapper(user, follow_error_msg, active_clients_ptr, 1);
            }
        }
    }
}

// Check if a network newline is present in a string.
int find_network_newline(const char *buf, int n)
{
    for (int i = 0; i < n + 1; i++)
    {
        if (buf[i] == '\r' && buf[i + 1] == '\n')
        {
            return i + 2;
        }
    }
    return -1;
}

// Show the past messages of all the users this user follows.
void show_past_messages(struct client **active_clients_ptr, struct client *user)
{
    for (int i = 0; i < FOLLOW_LIMIT; i++)
    {
        if (user->following[i] != NULL)
        {
            // Find indexes in the followed user's messages array
            // that do not consist of empty strings.
            for (int m = 0; m < MSG_LIMIT; m++)
            {
                if ((user->following[i])->message[m][0] != '\0')
                {
                    char user_message[BUF_SIZE];
                    strcpy(user_message, (user->following[i])->username);
                    strcat(user_message, " wrote: ");
                    strcat(user_message, (user->following[i])->message[m]);
                    strcat(user_message, "\r\n");
                    write_wrapper(user, user_message, active_clients_ptr, 1);
                }
            }
        }
    }
}

void unfollow_command(struct client *p, struct client *active_clients)
{
    // Since strtok breaks the string into tokens based on the delimiter,
    // a username with spaces would be split up. Therefore, the username
    // needs to be pieced together.
    char username[BUF_SIZE] = {'\0'};
    char *user_fragment = strtok(NULL, " ");
    // Check if the user does not supply a username.
    if (user_fragment == NULL)
    {
        // handle invalid use of the unfollow command
        char message[BUF_SIZE] = "Usage: unfollow username\r\n";
        write_wrapper(p, message, &active_clients, 1);
    }
    else
    {
        // Piece together the username to be unfollowed.
        strcat(username, user_fragment);
        user_fragment = strtok(NULL, " ");
        while (user_fragment != NULL)
        {
            strcat(username, " ");
            strcat(username, user_fragment);
            user_fragment = strtok(NULL, " ");
        }
        unfollow_user(p, &active_clients, username);
    }
    // Clear the buffer to prepare for the next read.
    p->inbuf[0] = '\0';
}

void follow_command(struct client *p, struct client *active_clients)
{
    // Since strtok breaks the string into tokens based on the delimiter,
    // a username with spaces would be split up. Therefore, the username
    // needs to be pieced together.
    char username[BUF_SIZE] = {'\0'};
    char *user_fragment = strtok(NULL, " ");
    if (user_fragment == NULL)
    {
        // handle invalid use of the follow command
        char message[BUF_SIZE] = "Usage: follow username\r\n";
        write_wrapper(p, message, &active_clients, 1);
    }
    else
    {
        // Piece together the username.
        strcat(username, user_fragment);
        user_fragment = strtok(NULL, " ");
        while (user_fragment != NULL)
        {
            strcat(username, " ");
            strcat(username, user_fragment);
            user_fragment = strtok(NULL, " ");
        }
        follow_user(p, &active_clients, username);
    }
    // Clear the buffer to prepare for the next read.
    p->inbuf[0] = '\0';
}

void send_command(struct client *p, struct client *active_clients)
{
    char message[141] = {"\0"};
    char *msg_fragment = strtok(NULL, " ");
    // Check if the message is empty or blank.
    if (msg_fragment == NULL)
    {
        char send_usage[BUF_SIZE] = "Message cannot be blank.\r\n";
        write_wrapper(p, send_usage, &active_clients, 1);
    }
    else
    {
        // Piece together the message.
        strcat(message, msg_fragment);
        msg_fragment = strtok(NULL, " ");
        while (msg_fragment != NULL)
        {
            strcat(message, " ");
            strcat(message, msg_fragment);
            msg_fragment = strtok(NULL, " ");
        }
        send_to_followers(p, message, &active_clients);
    }
    // Clear the buffer for the next read.
    p->inbuf[0] = '\0';
}

void show_command(struct client *p, struct client *active_clients)
{
    // Check if the user typed something after show.
    if (strtok(NULL, " ") != NULL)
    {
        char message[BUF_SIZE] = "Command show takes no arguments.\r\n";
        write_wrapper(p, message, &active_clients, 1);
    }
    else
    {
        show_past_messages(&active_clients, p);
    }
    // Clear the user's buffer for the next read.
    p->inbuf[0] = '\0';
}

int main(int argc, char **argv)
{
    int clientfd, maxfd, nready;
    struct client *p;
    struct sockaddr_in q;
    fd_set rset;

    // If the server writes to a socket that has been closed, the SIGPIPE
    // signal is sent and the process is terminated. To prevent the server
    // from terminating, ignore the SIGPIPE signal.
    struct sigaction sa;
    sa.sa_handler = SIG_IGN;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGPIPE, &sa, NULL) == -1)
    {
        perror("sigaction");
        exit(1);
    }

    // A list of active clients (who have already entered their names).
    struct client *active_clients = NULL;

    // A list of clients who have not yet entered their names. This list is
    // kept separate from the list of active clients, because until a client
    // has entered their name, they should not issue commands or
    // or receive announcements.
    struct client *new_clients = NULL;

    struct sockaddr_in *server = init_server_addr(PORT);
    int listenfd = set_up_server_socket(server, LISTEN_SIZE);
    free(server);

    // Initialize allset and add listenfd to the set of file descriptors
    // passed into select
    FD_ZERO(&allset);
    FD_SET(listenfd, &allset);

    // maxfd identifies how far into the set to search
    maxfd = listenfd;

    while (1)
    {
        // make a copy of the set before we pass it into select
        rset = allset;

        nready = select(maxfd + 1, &rset, NULL, NULL, NULL);
        if (nready == -1)
        {
            perror("select");
            exit(1);
        }
        else if (nready == 0)
        {
            continue;
        }

        // check if a new client is connecting
        if (FD_ISSET(listenfd, &rset))
        {
            printf("A new client is connecting\n");
            clientfd = accept_connection(listenfd, &q);

            FD_SET(clientfd, &allset);
            if (clientfd > maxfd)
            {
                maxfd = clientfd;
            }
            printf("Connection from %s\n", inet_ntoa(q.sin_addr));
            add_client(&new_clients, clientfd, q.sin_addr);
            char *greeting = WELCOME_MSG;
            if (write(clientfd, greeting, strlen(greeting)) == -1)
            {
                fprintf(stderr,
                        "Write to client %s failed\n", inet_ntoa(q.sin_addr));
                remove_client(&new_clients, clientfd);
            }
        }

        // Check which other socket descriptors have something ready to read.
        // The reason we iterate over the rset descriptors at the top level and
        // search through the two lists of clients each time is that it is
        // possible that a client will be removed in the middle of one of the
        // operations. This is also why we call break after handling the input.
        // If a client has been removed, the loop variables may no longer be
        // valid.
        int cur_fd, handled;
        for (cur_fd = 0; cur_fd <= maxfd; cur_fd++)
        {
            if (FD_ISSET(cur_fd, &rset))
            {
                handled = 0;

                // Check if any new clients are entering their names
                for (p = new_clients; p != NULL; p = p->next)
                {
                    if (cur_fd == p->fd)
                    {
                        char buf[BUF_SIZE] = {'\0'};
                        int nbytes;
                        int where = 0;
                        if ((nbytes = read(p->fd, buf, sizeof(buf) - strlen(p->inbuf))) > 0)
                        {
                            printf("[%d] Read %d bytes.\n", p->fd, nbytes);
                            // Check if the entire input has been received.
                            if ((where = find_network_newline(buf, nbytes)) > 0)
                            {
                                printf("Found network newline.\n");
                                buf[where - 2] = '\0';
                            }
                            // Add the input to the user's buffer.
                            strcat(p->inbuf, buf);
                        }

                        // Check if the client socket read failed or a system error occurred.
                        if (nbytes == 0)
                        {
                            fprintf(stderr,
                                    "Read from client %s failed\n", inet_ntoa(p->ipaddr));
                            remove_client(&new_clients, p->fd);
                        }
                        else if (nbytes == -1)
                        {
                            perror("read");
                            exit(1);
                        }
                        // where > 0 means a network newline has been found.
                        else if (where > 0)
                        {
                            if (strlen(p->inbuf) > 0)
                            {
                                struct client *active_clients_ptr;
                                // Check that the given username does not match the username of an existing username.
                                for (active_clients_ptr = active_clients; active_clients_ptr &&
                                                                          strcmp(active_clients_ptr->username, p->inbuf) != 0;
                                     active_clients_ptr = active_clients_ptr->next)
                                    ;
                                // Success. Username is valid, so activate the user.
                                if (active_clients_ptr == NULL)
                                {
                                    strcpy(p->username, p->inbuf);
                                    activate_client(p, &active_clients, &new_clients);
                                    handled = 1;
                                    // Clear the user's buffer for the next read.
                                    p->inbuf[0] = '\0';
                                    break;
                                }
                                else
                                {
                                    char *username_error = "Username is already taken. Please enter a new username.\r\n";
                                    write_wrapper(p, username_error, &new_clients, 0);
                                }
                            }
                            else if (strlen(p->inbuf) == 0)
                            {
                                char *username_error = "Username cannot be empty.\r\n";
                                write_wrapper(p, username_error, &new_clients, 0);
                            }
                            p->inbuf[0] = '\0';
                        }
                    }
                }
                if (!handled)
                {
                    // Check if this socket descriptor is an active client
                    for (p = active_clients; p != NULL; p = p->next)
                    {
                        if (cur_fd == p->fd)
                        {
                            char buf[BUF_SIZE] = {'\0'};
                            int nbytes;
                            int where = 0;
                            if ((nbytes = read(p->fd, buf, sizeof(buf) - strlen(p->inbuf))) > 0)
                            {
                                printf("[%d] Read %d bytes.\n", p->fd, nbytes);
                                // Handle partial reads.
                                if ((where = find_network_newline(buf, nbytes)) > 0)
                                {
                                    printf("Found network newline.\n");
                                    buf[where - 2] = '\0';
                                }
                                // Add the read input to the user's buffer.
                                strcat(p->inbuf, buf);
                            }

                            if (nbytes == 0)
                            {
                                fprintf(stderr,
                                        "Read from client %s failed\n", inet_ntoa(p->ipaddr));
                                // Since the user is now an active client, we must announce when 
                                // it disconnects.
                                announce_disconnect(&active_clients, p->username, p->fd);
                            }
                            else if (nbytes == -1)
                            {
                                perror("read");
                                exit(1);
                            }
                            else if (where > 0)
                            {
                                char *command = strtok(p->inbuf, " ");
                                // Check if the command input is empty.
                                if (command == NULL)
                                {
                                    char *error_message = "Invalid command.\r\n";
                                    write_wrapper(p, error_message, &active_clients, 1);
                                    p->inbuf[0] = '\0';
                                }
                                // Check for various command keywords.
                                else if (strcmp(command, "quit") == 0)
                                {
                                    announce_disconnect(&active_clients, p->username, p->fd);
                                }
                                else if (strcmp(command, "follow") == 0)
                                {
                                    follow_command(p, active_clients);
                                }
                                else if (strcmp(command, "unfollow") == 0)
                                {
                                    unfollow_command(p, active_clients);
                                }
                                else if (strcmp(command, "send") == 0)
                                {
                                    send_command(p, active_clients);
                                }
                                else if (strcmp(command, "show") == 0)
                                {
                                    show_command(p, active_clients);
                                }
                                // If the else is reached, then the client entered a command
                                // that does not exist.
                                else
                                {
                                    char error_message[BUF_SIZE] = "Invalid command.\r\n";
                                    write_wrapper(p, error_message, &active_clients, 1);
                                    p->inbuf[0] = '\0';
                                }
                            }
                            break;
                        }
                    }
                }
            }
        }
    }
    return 0;
}
