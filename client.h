#ifndef CLIENT_H_
#define CLIENT_H_

#include <netinet/in.h>
#include <sys/socket.h>

#include <gtk/gtk.h>

#include <event2/event.h>

typedef struct Client
{
    struct event_base *base;
    struct bufferevent *bev;
    struct sockaddr_in sin;
    GtkWidget *statusButton;
    GtkWidget *plainTextLog;
    GtkWidget *cipherTextLog;
} Client;

struct Client* client_init_new(
    GtkWidget *statusButton,
    GtkWidget *plainTextLog,
    GtkWidget *cipherTextLog,
    GtkWidget *portNumber,
    GtkWidget *serverName
);
void client_send(struct Client *client, const char *msg);
void client_free(struct Client *client);

#endif