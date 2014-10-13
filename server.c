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
#include <math.h>

#include "crypto.h"
#include "utils.h"
#include "server.h"

#define MAX_LINE 16384

void server_send(Server *this, const char *msg)
{
    struct evbuffer *output = bufferevent_get_output(this->bev);
    if(this->sessionKey != NULL)
    {
        char encryptedMessage[1024] = {};
        encrypt((char *)msg, encryptedMessage, this->sessionKey);
        char line[1024] = {};
        sprintf(line, "Sending message: '%s' as encrypted text:", msg );
        writeLine(this->plainTextLog, line);
        writeHex(this->plainTextLog, encryptedMessage, strlen(encryptedMessage));
        evbuffer_add_printf(output, "%s\n", encryptedMessage);
    }
    else
    {
        evbuffer_add_printf(output, "%s\n", msg);
    }
}

void server_send_data(Server *this, const void *data, size_t size)
{
    if(this != NULL && this->bev != NULL)
    {
        struct evbuffer *output = bufferevent_get_output(this->bev);
        if(output != NULL)
        {
            evbuffer_add(output, data, size);
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
        char decryptedMessage[1024] = {};
        decrypt(line, decryptedMessage, this->sessionKey);
        writeLine(this->plainTextLog, "Encrypted text received:");
        writeHex(this->plainTextLog, line, strlen(line));
        writeLine(this->plainTextLog, decryptedMessage);
        free(line);
    }
}

// The client should be sending E("Alice", Rb, g^a mod p, KAB)
void serverReadStateTestAuthentication(Server *this)
{
    struct evbuffer *input;
    char *line;
    size_t len;
    input = bufferevent_get_input(this->bev);

    // Encrypted message
    line = evbuffer_readln(input, &len, EVBUFFER_EOL_LF);

    writeLine(this->plainTextLog, "Encrypted received MESSAGE:");
    writeHex(this->plainTextLog, line, strlen(line));

    char decryptedMessage[1024] = {};
    decrypt(line, decryptedMessage, this->sharedPrivateKey);

    writeLine(this->plainTextLog, "DECRYPTED MESSAGE:");
    writeHex(this->plainTextLog, decryptedMessage, strlen(decryptedMessage));

    char *sender = strtok(decryptedMessage, "\n");
    char *returnedNonce = strtok(NULL, "\n");
    char *clientDiffieHellmanValue = strtok(NULL, "\n");

    char output[1024] = {};
    sprintf(output, "Sender: %s\n\nDH Val: %s\n", sender, clientDiffieHellmanValue);

    writeLine(this->plainTextLog, output);

    if(strcmp(sender, "Client") == 0)
    {
        writeLine(this->plainTextLog, "Message came from the client");

        if(are_nonces_equal(this->nonce, returnedNonce))
        {
            writeLine(this->plainTextLog, "Client returned correct Nonce");
            int dhVal = atoi(clientDiffieHellmanValue);

            // This will be the key used for communication in the future
            int sessionKeyInt = (int) pow(dhVal, B);
            char sessionKeyString[20] = {};
            sprintf(sessionKeyString, "%d", sessionKeyInt);

            this->sessionKey = key_init_new();
            this->sessionKey->data = get_md5_hash(sessionKeyString, strlen(sessionKeyString));
            if(this->sessionKey->data == NULL)
            {
                printf("NULL\n");
                return;
            }
            this->sessionKey->length = strlen(this->sessionKey->data);

            writeLine(this->plainTextLog, "Session key:");
            writeHex(this->plainTextLog, this->sessionKey->data, this->sessionKey->length);

            this->authState = AUTH_STATE_AUTHENTICATED;
        }
    }
}

// The client should be sending us their public key Ra
void serverReadStateNoAuthentication(Server *this)
{
    // Rb nonce
    this->nonce = get_nonce();
    writeLine(this->plainTextLog,"Sending NONCE:");
    writeHex(this->plainTextLog, this->nonce, NONCE_SIZE);
    server_send_data(this, this->nonce, NONCE_SIZE);

    // Ra nonce
    char clientNonce[NONCE_SIZE] = {};
    bufferevent_read(this->bev, clientNonce, NONCE_SIZE);

    writeLine(this->plainTextLog, "NONCE RECEIVED:");
    writeHex(this->plainTextLog, clientNonce, NONCE_SIZE);
    
    int diffieHellmanVal = (int) pow(DIFFIE_HELLMAN_G, B) % DIFFIE_HELLMAN_P;
    char output[30] = {};
    sprintf(output, "g^b mod p: %d", diffieHellmanVal);
    writeLine(this->plainTextLog, output);

    char messageToEncrypt[30] = {};
    sprintf(messageToEncrypt, "Server\n%s\n%d\n", clientNonce, diffieHellmanVal);

    writeLine(this->plainTextLog, "Message to Encrypt:");
    writeHex(this->plainTextLog, messageToEncrypt, strlen(messageToEncrypt));

    char encryptedMessage[30] = {};
    encrypt(messageToEncrypt, encryptedMessage, this->sharedPrivateKey);

    writeLine(this->plainTextLog, "Encrypted Message:");
    writeHex(this->plainTextLog, encryptedMessage, strlen(encryptedMessage));

    char fullMessage[30] = {};
    sprintf(fullMessage, "%s\n%s\n", this->nonce, encryptedMessage);

    writeLine(this->plainTextLog, "Final Message to Send:");
    writeHex(this->plainTextLog, fullMessage, strlen(fullMessage));

    server_send(this, fullMessage);

    this->authState = AUTH_STATE_TEST;
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

    this->sessionKey = NULL;

    this->sharedPrivateKey = key_init_new();
    const char *keyText = gtk_entry_get_text(GTK_ENTRY(this->sharedKey));
    this->sharedPrivateKey->length = strlen(keyText);
    this->sharedPrivateKey->data = malloc(this->sharedPrivateKey->length);
    strcpy(this->sharedPrivateKey->data, keyText);

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