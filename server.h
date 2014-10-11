#ifndef SERVER_H_
#define SERVER_H_

#include <netinet/in.h>
#include <sys/socket.h>

#include <event2/event.h>

#define AUTH_STATE_NONE 0
#define AUTH_STATE_TEST 1
#define AUTH_STATE_AUTHENTICATED 2

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
    GtkWidget *sharedKey;
    int authState;
    unsigned char *privateKey;
    unsigned char *publicKey;
} Server;

struct Server* server_init_new(
    GtkWidget *statusButton,
    GtkWidget *plainTextLog,
    GtkWidget *cipherTextLog,
    GtkWidget *portNumber,
    GtkWidget *serverName,
    GtkWidget *sharedKey
);
void server_free(struct Server *server);
void server_send(struct Server *server, const char *msg);
gboolean server_event_loop(struct Server* server);
void serverReadStateAuthenticated(struct Server *server);
void serverReadStateNoAuthentication(struct Server *server);
void serverReadStateTestAuthentication(struct Server *server);

#endif