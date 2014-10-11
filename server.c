#include <event2/event.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>

#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <fcntl.h>

#include <gtk/gtk.h>

#include <assert.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include "crypto.h"
#include "utils.h"
#include "server.h"

#define MAX_LINE 16384

void server_send(Server *this, const char *msg)
{
    if(this->bev != NULL)
    {
        struct evbuffer *output = bufferevent_get_output(this->bev);
        if(output != NULL)
        {
            evbuffer_add_printf(output, "%s\n", msg);
        }
    }   
}

void
server_readcb(struct bufferevent *bev, void *ctx)
{
    Server *this = ctx;

    switch(this->authState)
    {
        case AUTH_STATE_AUTHENTICATED:
            serverReadStateAuthenticated(this);
            break;
        case AUTH_STATE_TEST:
            serverReadStateTestAuthentication(this);
            break;
        default:
            serverReadStateNoAuthentication(this);
            break;
    }
}

// The client is authenticated now write out the messages as they come in
void serverReadStateAuthenticated(Server *this)
{
    struct evbuffer *input;
    char *line;
    size_t n;
    input = bufferevent_get_input(this->bev);
    while ((line = evbuffer_readln(input, &n, EVBUFFER_EOL_LF))) {
        writeLine(this->plainTextLog, line);
        free(line);
    }
}

// The client should be sending E("Alice", Rb, g^a mod p, KAB)
void serverReadStateTestAuthentication(Server *this)
{
    struct evbuffer *input;
    char *line;
    size_t n;
    input = bufferevent_get_input(this->bev);
    while ((line = evbuffer_readln(input, &n, EVBUFFER_EOL_LF))) {
        free(line);
    }
}

// The client should be sending us their public key Ra
void serverReadStateNoAuthentication(Server *this)
{
    struct evbuffer *input;
    char *line;
    size_t len;
    input = bufferevent_get_input(this->bev);

    // Ra
    line = evbuffer_readln(input, &len, EVBUFFER_EOL_LF);
    unsigned char *clientPublicKey = malloc(len);
    memcpy(clientPublicKey, line, len);
    unsigned char *message = NULL;
    public_encrypt(clientPublicKey, len, clientPublicKey, message);

    server_send(this, (char *) message);

    while ((line = evbuffer_readln(input, &len, EVBUFFER_EOL_LF))) {
        free(line);
    }
}

void server_errorcb(struct bufferevent *bev, short error, void *ctx)
{
    //Server *this = ctx;
    if (error & BEV_EVENT_EOF) {
        /* connection has been closed, do any clean up here */
    } else if (error & BEV_EVENT_ERROR) {
        /* check errno to see what error occurred */
    } else if (error & BEV_EVENT_TIMEOUT) {
        /* must be a timeout event handle, handle it */
    }
    bufferevent_free(bev);
}

void server_do_accept(evutil_socket_t listener, short event, void *arg)
{
    Server *this = arg;
    struct sockaddr_storage ss;
    socklen_t slen = sizeof(ss);
    int fd = accept(listener, (struct sockaddr *)&ss, &slen);
    if (fd < 0)   // XXXX eagain??
    {
        perror("accept");
    }
    else if (fd > FD_SETSIZE)
    {
        close(fd); // XXX replace all closes with EVUTIL_CLOSESOCKET */
    }
    else
    {
        struct bufferevent *bev;
        evutil_make_socket_nonblocking(fd);

        bev = bufferevent_socket_new(this->eventBase, fd, BEV_OPT_CLOSE_ON_FREE);
        if(bev == NULL)
        {
            printf("FAILED TO CREATE BEV");
            return;
        }
        bufferevent_setcb(bev, server_readcb, NULL, server_errorcb, this);
        bufferevent_setwatermark(bev, EV_READ, 0, MAX_LINE);
        bufferevent_enable(bev, EV_READ|EV_WRITE);

        this->bev = bev;
    }
}

gboolean server_event_loop(Server* server)
{
    if(server != NULL && server->eventBase != NULL)
    {
        event_base_loop(server->eventBase, EVLOOP_NONBLOCK);
        return TRUE;
    }
    return FALSE;
}

struct Server* server_init_new(
    GtkWidget *statusButton,
    GtkWidget *plainTextLog,
    GtkWidget *cipherTextLog,
    GtkWidget *portNumber,
    GtkWidget *serverName,
    GtkWidget *sharedKey
)
{
    Server *this = malloc(sizeof(Server));

    this->plainTextLog = plainTextLog;
    this->cipherTextLog = cipherTextLog;
    this->statusButton = statusButton;
    this->sharedKey = sharedKey;
    this->authState = AUTH_STATE_NONE;
    this->bev = NULL;

    generate_key(this->publicKey, this->privateKey);

    this->eventBase = event_base_new();
    if (!this->eventBase)
    {
        perror("base");
        return NULL;
    }

    const char *portNumberString = gtk_entry_get_text(GTK_ENTRY(portNumber));
    int port = atoi(portNumberString);

    const char *serverNameString = gtk_entry_get_text(GTK_ENTRY(serverName));

    this->sin.sin_family = AF_INET;
    inet_aton(serverNameString, &(this->sin.sin_addr));
    this->sin.sin_port = htons(port);
    memset(&(this->sin.sin_zero), '\0', 8); // zero the rest of the struct 

    this->listener = socket(AF_INET, SOCK_STREAM, 0);
    evutil_make_socket_nonblocking(this->listener);

#ifndef WIN32
    {
        int one = 1;
        setsockopt(this->listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    }
#endif

    if (bind(this->listener, (struct sockaddr *)&this->sin, sizeof(this->sin)) < 0)
    {
        perror("bind");
        return NULL;
    }

    if (listen(this->listener, 16) < 0)
    {
        perror("listen");
        return NULL;
    }

    this->listener_event = event_new(this->eventBase, this->listener, EV_READ | EV_PERSIST, server_do_accept, (void *)this);
    event_add(this->listener_event, NULL);

    g_idle_add((GSourceFunc)server_event_loop, this);

    gtk_button_set_label(GTK_BUTTON(this->statusButton), "Running");

    return this;
}

void server_free(Server *this)
{
    if(this == NULL)
    {
        return;
    }

    gtk_button_set_label(GTK_BUTTON(this->statusButton), "Start!");

    g_idle_remove_by_data(this);
    if(this->bev != NULL)
    {
        bufferevent_free(this->bev);
    }
    evutil_closesocket(this->listener);
    event_free(this->listener_event);
    this->listener_event = NULL;
    event_base_free(this->eventBase);
    this->eventBase = NULL;
    free(this);
    this = NULL;
}