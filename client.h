#ifndef CLIENT_H_
#define CLIENT_H_

#include <netinet/in.h>
#include <sys/socket.h>

#include <gtk/gtk.h>

#include <event2/event.h>

#define AUTH_STATE_NONE 0
#define AUTH_STATE_TEST 1
#define AUTH_STATE_AUTHENTICATED 2

typedef struct Client
{
    struct event_base *base;
    struct bufferevent *bev;
    struct sockaddr_in sin;
    GtkWidget *statusButton;
    GtkWidget *plainTextLog;
    GtkWidget *cipherTextLog;
    GtkWidget *sharedKey;
    int authState;
    unsigned char *privateKey;
    unsigned char *publicKey;
} Client;

struct Client* client_init_new(
    GtkWidget *statusButton,
    GtkWidget *plainTextLog,
    GtkWidget *cipherTextLog,
    GtkWidget *portNumber,
    GtkWidget *clientName,
    GtkWidget *sharedKey
);
void client_send(struct Client *client, const char *msg);
void client_free(struct Client *client);
void clientReadStateAuthenticated(struct Client *client);
void clientReadStateNoAuthentication(struct Client *client);
void clientReadStateTestAuthentication(struct Client *client);

#endif