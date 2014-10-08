#ifndef SERVER_H_
#define SERVER_H_

#include <netinet/in.h>
#include <sys/socket.h>

#include <event2/event.h>

typedef struct Server
{
    struct event_base *eventBase;
    evutil_socket_t listener;
    struct sockaddr_in sin;
    struct event *listener_event;
    struct bufferevent *bev;
    GtkWidget *statusButton;
    GtkWidget *plainTextLog;
    GtkWidget *cipherTextLog;
} Server;

struct Server* server_init_new(
    GtkWidget *statusButton,
    GtkWidget *plainTextLog,
    GtkWidget *cipherTextLog,
    GtkWidget *portNumber,
    GtkWidget *serverName
);
void server_free(struct Server *server);
void server_send(struct Server *server, const char *msg);
gboolean server_event_loop(struct Server* server);

#endif