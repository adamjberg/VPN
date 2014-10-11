#include <event2/event.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>

#include <string.h>
#include <stdlib.h>

#include <gtk/gtk.h>

#include "crypto.h"
#include "utils.h"
#include "client.h"

#define MAX_LINE 16384

gboolean client_event_loop(Client* this)
{
    if(this != NULL && this->base != NULL)
    {
        event_base_loop(this->base, EVLOOP_NONBLOCK);
        return TRUE;
    }
    return FALSE;
}

void set_tcp_no_delay(evutil_socket_t fd)
{
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY,
               &one, sizeof one);
    evutil_make_socket_nonblocking(fd);
}

void client_readcb(struct bufferevent *bev, void *ctx)
{
    Client *this = ctx;

    switch(this->authState)
    {
        case AUTH_STATE_AUTHENTICATED:
            clientReadStateAuthenticated(this);
            break;
        case AUTH_STATE_TEST:
            clientReadStateTestAuthentication(this);
            break;
        default:
            clientReadStateNoAuthentication(this);
            break;
    }
}

// The server is authenticated now write out the messages as they come in
void clientReadStateAuthenticated(Client *this)
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

// The server should be sending E("", Rb, g^a mod p, KAB)
void clientReadStateTestAuthentication(Client *this)
{
    struct evbuffer *input;
    char *line;
    size_t n;
    input = bufferevent_get_input(this->bev);
    while ((line = evbuffer_readln(input, &n, EVBUFFER_EOL_LF))) {
        free(line);
    }
}

// The server should be sending us their public key
// and E("Bob", Ra, g^b mod p, KAB)
void clientReadStateNoAuthentication(Client *this)
{
    struct evbuffer *input;
    char *line;
    size_t len;
    input = bufferevent_get_input(this->bev);

    // Rb
    line = evbuffer_readln(input, &len, EVBUFFER_EOL_LF);
    unsigned char *Rb = malloc(len);
    memcpy(Rb, line, len);

    printf("RB: %s", Rb);

    // E(Ra)
    line = evbuffer_readln(input, &len, EVBUFFER_EOL_LF);

    // E(g^b mod p)
    line = evbuffer_readln(input, &len, EVBUFFER_EOL_LF);

    // E(KAB)
    line = evbuffer_readln(input, &len, EVBUFFER_EOL_LF);



    while ((line = evbuffer_readln(input, &len, EVBUFFER_EOL_LF))) {
        free(line);
    }
}

void client_eventcb(struct bufferevent *bev, short events, void *ptr)
{
    Client *this = ptr;
    if (events & BEV_EVENT_CONNECTED)
    {
        gtk_button_set_label(GTK_BUTTON(this->statusButton), "Connected");
        evutil_socket_t fd = bufferevent_getfd(bev);
        set_tcp_no_delay(fd);
        client_send(this, (char *) this->publicKey);
    }
    else if (events & BEV_EVENT_ERROR)
    {
        gtk_button_set_label(GTK_BUTTON(this->statusButton), "Connect!");
        g_idle_remove_by_data(this);
    }
}

void client_send(Client* this, const char *msg)
{
    if(this != NULL && this->bev != NULL)
    {
        struct evbuffer *output = bufferevent_get_output(this->bev);
        if(output != NULL)
        {
            evbuffer_add_printf(output, "%s\n", msg);
        }
    }
}

Client* client_init_new(
    GtkWidget *statusButton,
    GtkWidget *plainTextLog,
    GtkWidget *cipherTextLog,
    GtkWidget *portNumber,
    GtkWidget *serverName,
    GtkWidget *sharedKey
)
{
    Client *this = malloc(sizeof(Client));

    this->plainTextLog = plainTextLog;
    this->cipherTextLog = cipherTextLog;
    this->statusButton = statusButton;
    this->sharedKey = sharedKey;

    generate_key(this->publicKey, this->privateKey);

    const char *portNumberString = gtk_entry_get_text(GTK_ENTRY(portNumber));
    int port = atoi(portNumberString);

    const char *serverNameString = gtk_entry_get_text(GTK_ENTRY(serverName));

    this->base = event_base_new();
    if (!this->base)
    {
        printf("Failed to create base");
        client_free(this);
        return NULL;
    }

    memset(&this->sin, 0, sizeof(this->sin));
    this->sin.sin_family = AF_INET;
    inet_aton(serverNameString, &(this->sin.sin_addr));
    this->sin.sin_port = htons(port);

    this->bev = bufferevent_socket_new(this->base, -1, BEV_OPT_CLOSE_ON_FREE);
    if(this->bev == NULL)
    {
        printf("Failed to create bev");
        client_free(this);
        return NULL;
    }

    bufferevent_setcb(this->bev, client_readcb, NULL, client_eventcb, this);
    bufferevent_enable(this->bev, EV_READ | EV_WRITE);

    if (bufferevent_socket_connect(this->bev,
        (struct sockaddr *)&this->sin, sizeof(this->sin)) < 0)
    {
        printf("Failed to connect");
        client_free(this);
        return NULL;
    }

    g_idle_add((GSourceFunc)client_event_loop, this);

    return this;
}

void client_free(Client *this)
{
    gtk_button_set_label(GTK_BUTTON(this->statusButton), "Connect!");
    if(this == NULL)
    {
        return;
    }

    g_idle_remove_by_data(this);
    if(this->bev != NULL)
    {
        bufferevent_free(this->bev);
    }
    event_base_free(this->base);
    free(this);
}