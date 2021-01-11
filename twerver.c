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
    #define PORT 56029
#endif

#define LISTEN_SIZE 5
#define WELCOME_MSG "Welcome to CSC209 Twitter! Enter your username: \r\n"
#define SEND_MSG "send"
#define SHOW_MSG "show"
#define FOLLOW_MSG "follow"
#define UNFOLLOW_MSG "unfollow"
#define BUF_SIZE 256
#define MSG_LIMIT 8
#define FOLLOW_LIMIT 5

struct client {
    int fd;
    struct in_addr ipaddr;
    char username[BUF_SIZE];
    char message[MSG_LIMIT][BUF_SIZE];
    struct client *following[FOLLOW_LIMIT]; // Clients this user is following
    struct client *followers[FOLLOW_LIMIT]; // Clients who follow this user
    char inbuf[BUF_SIZE]; // Used to hold input from the client
    char *in_ptr; // A pointer into inbuf to help with partial reads
    struct client *next;
};


// Provided functions. 
void add_client(struct client **clients, int fd, struct in_addr addr);
void remove_client(struct client **clients, int fd);

// The set of socket descriptors for select to monitor.
// This is a global variable because we need to remove socket descriptors
// from allset when a write to a socket fails. 
fd_set allset;

/* 
 * Create a new client, initialize it, and add it to the head of the linked
 * list.
 */
void add_client(struct client **clients, int fd, struct in_addr addr) {
    struct client *p = malloc(sizeof(struct client));
    if (!p) {
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

    for (int i = 0; i < FOLLOW_LIMIT; i++) {
        p->followers[i] = NULL;
        p->following[i] = NULL;
    }

    // initialize messages to empty strings
    for (int i = 0; i < MSG_LIMIT; i++) {
        p->message[i][0] = '\0';
    }

    *clients = p;
}

/* 
 * Helper: Add to or remove client from the list of struct client.
 * Return 0 if successful, return 1 if client already in the list before adding,
 * return -1 if list exceed limit before adding, or client not in list when removing.
 */
int modify_followlist(struct client **list, struct client *client, char *action){

    //check if client already in the list before adding
    if (!strcmp(action,"add")){
        for(int index = 0; index < FOLLOW_LIMIT; index++){
            if (list[index] != NULL && list[index]->fd == client->fd){
                return 1;
            }
        }
    }

    for(int index = 0; index < FOLLOW_LIMIT; index++){
        if (!strcmp(action,"add") && list[index] == NULL){
            list[index] = client;
            return 0;
        }

        if (!strcmp(action,"remove") && list[index] != NULL
            && list[index]->fd == client->fd){
            list[index] = NULL;
            return 0;
        }
    }
    return -1;
}

/* 
 * Remove client from the linked list and close its socket.
 * Also, remove socket descriptor from allset.
 */
void remove_client(struct client **clients, int fd) {
    struct client **p;

    for (p = clients; *p && (*p)->fd != fd; p = &(*p)->next)
        ;

    // Now, p points to (1) top, or (2) a pointer to another client
    if (*p) {

        // Remove the client from other clients' following/followers lists
        for (int index = 0; index < FOLLOW_LIMIT; index++){
            struct client *following = (*p)->following[index];

            if (following != NULL){
                modify_followlist(following->followers, *p, "remove");

                printf("%s is no longer following %s because they disconnected\n",
                    (*p)->username, following->username);
                printf("%s no longer has %s as a follower\n", following->username,
                    (*p)->username);
            }

            struct client *follower = (*p)->followers[index];
            if (follower != NULL){
                modify_followlist(follower->following, *p, "remove");

                printf("%s is no longer following %s because they disconnected\n",
                    follower->username, (*p)->username);
                printf("%s no longer has %s as a follower\n", (*p)->username,
                    follower->username);
            }
        }

        // Remove the client
        struct client *t = (*p)->next;
        printf("Removing client %d %s\n", fd, inet_ntoa((*p)->ipaddr));

        FD_CLR((*p)->fd, &allset);
        if (close((*p)->fd) == -1){
            perror("close");
            exit(1);
        }
        free(*p);

        *p = t;
    } else {
        fprintf(stderr, "Trying to remove fd %d, but I don't know about it\n", fd);
    }
}

/*
 * Helper: Search the first n characters of buf for a network newline (\r\n).
 * Return one plus the index of the '\n' of the first network newline,
 * or -1 if no network newline is found.)
 */
int find_network_newline(const char *buf, int n) {
    int i = 0;

    while (i < n-1) {
        if (buf[i] == '\r' && buf[i+1] == '\n')  return i+2;
        i++;
    }
    return -1;
}

/*
 * Read messages from client, and store in the client's inbuf.
 * Return 0 if receiving a network new line character, return -1 if the unsuccessful read.
 * Return 1 if no network new line received, and messages already read are stored in the
 * client's inbuf, which will be updated in next read.
 */
int buf_read(struct client* client){
    int current = strlen(client->inbuf);  // bytes currently in buf

    int nbytes = read(client->fd, client->in_ptr,  BUF_SIZE - current);

    if (nbytes < 0){
        fprintf(stderr, "read from client failed\n");
        exit(1);

    }else if (nbytes == 0){
        printf("[%d] Read 0 bytes\n", client->fd);
        return -1;

    }else{
        printf("[%d] Read %d bytes\n", client->fd, nbytes);

        current += nbytes;
        int where;

        // Determine if a full line has been read from the client.
        if ((where = find_network_newline(client->inbuf, current)) > 0) {
            client->inbuf[where-2] = '\0';
            client->inbuf[where-1] = '\0';
            printf("[%d] Found newline: %s\n", client->fd, client->inbuf);
            return 0;
        }

        client->in_ptr += nbytes; //update in preparation for the next read.
        return 1;
    }
}

/* 
 * Helper: Find the client with username name in the linked list formed by sturct client. 
 * If found, return the pointer to this client in the list, else return NULL.
 */
struct client *find_client(struct client *list, char* name){
    struct client *curr;

    for(curr = list; curr && strcmp(curr->username, name); curr = curr->next)
        ;

    if (curr) {
        return curr;
    }
    return NULL;
}

/*
 * Helper: write note to client, return 0 if successful, return -1 if not.
 */
int write_to(char *note, struct client *client){
    if (write(client->fd, note, strlen(note)) == -1) {
        fprintf(stderr, "Write to client %s failed\n", inet_ntoa(client->ipaddr));
        return -1;
    }
    return 0;
}

/*
 * Read name from client input, if acceptable, store it to the client's username.
 * Return 0 if name is accpetable and stored, return -1 if read is unsuccessful,
 * return 1 if name is unaccetable or partial read, client haven't typed in entire message. 
 */
int read_name(struct client *active_clients, struct client *client){
    int r = buf_read(client);

    if (r == 0){
        char buf [BUF_SIZE];
        strcpy(buf, client->inbuf); //store client's inbuf to buf
        buf[BUF_SIZE-1] = '\0';

        //update inbuf pointer so that in next read, client's inbuf will be rewrite.
        client->in_ptr = client->inbuf;

        if (!strcmp(buf, "") || find_client(active_clients, buf)){
            char *note = "Name can't be empty or taken by other users already, please enter name again.\r\n";
            if (write_to(note, client) == -1){
                return -1;
            }
            return 1;
        }

        strcpy(client->username, buf);
        return 0;
    }else if (r == -1){
        return -1;
    }else{
        return 1;
    }
}

/*
 * Helper: Add message "msg" to the message list.
 * Return 0 if added successfully, return -1 if message list already exceed limit length.
 */
int add_msg(char list[MSG_LIMIT][BUF_SIZE], char msg[BUF_SIZE]){
    for(int index = 0; index < MSG_LIMIT; index++){
        if (!strcmp(list[index], "")){
            strcpy(list[index], msg+5);
            list[index][BUF_SIZE-1] = '\0';
            return 0;
        }
    }
    return -1;
}

/*
 * Helper: announce s to each follower in the followers list.
 */
void announce_follow(struct client *followers[FOLLOW_LIMIT], char *s){
   for(int index = 0; index < FOLLOW_LIMIT; index++){
        if (followers[index] != NULL){
            write_to(s, followers[index]);
        }
   }
}

/*
 * Process "send" message (stored in buf) from client, announce the message to each follower 
 * in the client's followers list. If exceed maximum message length, notify the client.
 * Return 0 if successful announce or notify, return -1 if not.
 */
int process_send(struct client *active_clients, struct client *client, char buf[BUF_SIZE]){
    if (add_msg(client->message, buf) == 0){

        printf("%s: %s\n", client->username, buf);

        char note[2*BUF_SIZE+2];

        strcpy(note, client->username);
        strcat(note, ": ");
        strcat(note, buf + 5);
        strcat(note, "\r\n");

        announce_follow(client->followers, note);
    }else{
        char *note = "You already sent maximum number of messages.\r\n";
        if (write_to(note, client) == -1){
            return -1;
        }
    }
    return 0;
}

/*
 * Process "show" message (stored in buf) from client, displays the previously sent messages of
 * those users this user is following. Return 0 if successful, return -1 if not.
 */
int process_show(struct client *active_clients, struct client *client, char buf[BUF_SIZE]){
    printf("%s: show\n", client->username);
    for (int index = 0; index < FOLLOW_LIMIT; index++){

        struct client *p = client->following[index];

        if (p != NULL){

            for (int i = 0; strcmp(p->message[i], ""); i++){
                char msg[strlen(p->username) + strlen(p->message[i]) + 8];

                strcpy(msg, p->username);
                strcat(msg, " wrote: ");
                strcat(msg, p->message[i]);
                strcat(msg, "\r\n");

                if (write_to(msg, client) == -1){
                    return -1;
                }
            }
        }
    }
    return 0;
}

/* 
 * Helper:  Find length of the following or follower list.
 */
int follow_length(struct client *list[FOLLOW_LIMIT]){
    int count = 0;

    for(int index = 0; index < FOLLOW_LIMIT; index++){
        if (list[index] != NULL){
            count += 1;
        }
    }
    return count;
}


/* 
 * Process "follow" message (stored in buf) from client. Add the user that the client wants to
 * follow to client's following list, and add the client to the user's follower list. 
 * Notify client if client's following list or the user's follower list doesn't have sufficient 
 * space, or the user does not exit 
 * or already in the following list.(Client can follow himself.)  
 * Return 0 if successful, return -1 if not.
 */
int process_follow(struct client *active_clients, struct client *client, char buf[BUF_SIZE]){
    if (follow_length(client->following) >= FOLLOW_LIMIT){
        char *note = "You already follow maximum number of users.\r\n";
        if (write_to(note, client) == -1){
            return -1;
        }
    }else {

        char name[BUF_SIZE];
        memcpy(name, &buf[7], BUF_SIZE-1); // store the username that client wants to follow
        name[BUF_SIZE-1] = '\0';

        // check if the user in the active_clients list.
        struct client *following = find_client(active_clients, name);

        if (following == NULL){
            char *note = "The user you want to unfollow does not exit or not active now.\r\n";
            if (write_to(note, client) == -1){
                return -1;
            }

        }else if (follow_length(following->followers) >= FOLLOW_LIMIT){
            char *note = "The user you try to follow already has maximum number of followers.\r\n";
            if (write_to(note, client) == -1){
                return -1;
            }

        }else{
            // If the user already in the following list, modify_followlist returns 1.
            if (modify_followlist(client->following, following, "add") == 1){
                char *note = "The user you try to follow is already in your following list.\r\n";
                if (write_to(note, client) == -1){
                   return -1;
                }

            }else{
                modify_followlist(following->followers, client, "add");

                printf("%s: follow %s\n", client->username, name);
                printf("%s is following %s\n", client->username, name);
                printf("%s has %s as a follower\n", name, client->username);
            }
        }
    }
    return 0;
}

/* 
 * Process "unfollow" message (stored in buf) from client. Remove the user that the client wants to
 * unfollow from client's following list, and remove the client from the user's follower list. 
 * Notify client if the user does not exit or not in the following list.
 * Return 0 if successful, return -1 if not.
 */
int process_unfollow(struct client *active_clients, struct client *client, char buf[BUF_SIZE]){

    char name[BUF_SIZE];
    memcpy(name, &buf[9], BUF_SIZE-1); //store the username that client wants to unfollow
    name[BUF_SIZE-1] = '\0';

    struct client *unfollow = find_client(active_clients, name);

    if (unfollow == NULL){
        char *note = "The user you want to unfollow does not exit or not active now.\r\n";
        if (write_to(note, client) == -1){
            return -1;
        }
    }else{
        // If the user not in the following list, modify_followlist returns -1.
        if (modify_followlist(client->following, unfollow, "remove") == -1){
            char *note = "The user you try to unfollow is not in your following list.\r\n";
            if (write_to(note, client) == -1){
                return -1;
            }
        }

        modify_followlist(unfollow->followers, client, "remove");

        printf("%s: unfollow %s\n", client->username, name);
        printf("%s no longer has %s as a follower\n", name, client->username);
        printf("%s unfollows %s\n", client->username, name);
    }
    return 0;
}

/* 
 * Read and process commands depending on different kinds of messages client sent.
 * Return 0 if commands are successully handled, return -1 if read is unsuccessful.
 * Return 1 when partial read, client haven't typed in entire message.
 */
int read_commands(struct client *active_clients, struct client *client){
    int r = buf_read(client);
    if (r == 0){

        char buf [BUF_SIZE];
        strcpy(buf, client->inbuf); // store client's inbuf to buf
        buf[BUF_SIZE-1] = '\0';

        // update inbuf pointer so that in next read, client's inbuf will be rewrite.
        client->in_ptr = client->inbuf;

        if (!strncmp(buf, SEND_MSG, 4)){
            if (process_send(active_clients, client, buf) == -1){
                return -1;
            }

        }else if (!strncmp(buf, SHOW_MSG, 4)){
            if (process_show(active_clients, client, buf) == -1){
                return -1;
            }

        }else if (!strncmp(buf, FOLLOW_MSG, 6)){
            if (process_follow(active_clients, client, buf) == -1){
                return -1;
            }

        }else if (!strncmp(buf, UNFOLLOW_MSG, 8)){
            if (process_unfollow(active_clients, client, buf) == -1){
                return -1;
            }

        }else if (!strcmp(buf, "quit")){
            return -1;

        }else {
            printf("%s: %s\n", client->username, buf);
            printf("Invalid command\n");
            char *note = "Invalid command\r\n";
            if (write_to(note, client) == -1){
                return -1;
            }

        }
        return 0;
    }else if (r == -1){
        return -1;
    }else{
        return 1;
    }
}

/*
 * Announce s to each active client in active_clients list.
 */
void announce(struct client *active_clients, char *s){
    struct client *curr;

    for(curr = active_clients; curr; curr = curr->next){
        write_to(s, curr);
    }
}

/*
 *Move client c from new_clients list to active_clients list. 
 */
void activate_client(struct client *c,
    struct client **active_clients_ptr, struct client **new_clients_ptr){

    // remove c from new_clients list
    struct client **p;
    for (p = new_clients_ptr; *p && (*p)->fd != c->fd; p = &(*p)->next)
        ;
    if (*p) {
        struct client *t = (*p)->next;
        *p = t;
    }else {
        fprintf(stderr, "Try to remove client %s from new_clients list, but can't find it\n", inet_ntoa(c->ipaddr));
    }

    // add c to active_clients list
    c->next = *active_clients_ptr;
    *active_clients_ptr = c;
    }

int main (int argc, char **argv) {
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
    if (sigaction(SIGPIPE, &sa, NULL) == -1) {
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

    while (1) {
        // make a copy of the set before we pass it into select
        rset = allset;

        nready = select(maxfd + 1, &rset, NULL, NULL, NULL);
        if (nready == -1) {
            perror("select");
            exit(1);
        } else if (nready == 0) {
            continue;
        }

        // check if a new client is connecting
        if (FD_ISSET(listenfd, &rset)) {
            printf("A new client is connecting\n");
            clientfd = accept_connection(listenfd, &q);

            FD_SET(clientfd, &allset);
            if (clientfd > maxfd) {
                maxfd = clientfd;
            }
            printf("Connection from %s\n", inet_ntoa(q.sin_addr));
            add_client(&new_clients, clientfd, q.sin_addr);
            char *greeting = WELCOME_MSG;
            if (write(clientfd, greeting, strlen(greeting)) == -1) {
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
        for (cur_fd = 0; cur_fd <= maxfd; cur_fd++) {
            if (FD_ISSET(cur_fd, &rset)) {
                handled = 0;

                // Check if any new clients are entering their names
                for (p = new_clients; p != NULL; p = p->next) {
                    if (cur_fd == p->fd) {
                        //  handle input from a new client who has not yet entered an acceptable name
                        int r = read_name(active_clients, p);
                        if (r == 0){
                            // acceptable name already stored, move p to active client list                           
                            activate_client(p, &active_clients, &new_clients);

                            char note[strlen(p->username)+17];
                            strcpy(note, p->username);
                            strcat(note, " has just joined.");
                            printf("%s\n", note);
                            strcat(note, "\r\n");

                            announce(active_clients, note); // announce join of p to active clients            

                        }else if (r < 0){
                            // unsuccessful read, indicate disconnection from p
                            printf("Disconnect from %s/n", inet_ntoa(p->ipaddr));
                            remove_client(&new_clients, cur_fd);

                        } // else: partial read, wait for next input and read
                        handled = 1;
                        break;
                    }
                }

                if (!handled) {
                    // Check if this socket descriptor is an active client
                    for (p = active_clients; p != NULL; p = p->next) {
                        if (cur_fd == p->fd) {
                            // handle input from an active client
                            int r = read_commands(active_clients, p);

                            if (r < 0){

                                char name[strlen(p->username)+1];
                                strcpy(name, p->username);   // store p's username in name
                                name[strlen(p->username)] = '\0';

                                printf("Disconnect from %s\n", inet_ntoa(p->ipaddr));
                                remove_client(&active_clients, cur_fd);

                                char note[strlen(name)+9];
                                strcpy(note,"Goodbye ");
                                note[strlen(name)+8] = '\0';
                                strcat(note, name);
                                strcat(note, "\r\n");

                                announce(active_clients, note);   // announce Goodbye p to active clients
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
