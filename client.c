#include <event2/event.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>

#include <string.h>
#include <stdlib.h>
#include <math.h>

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
        char decryptedMessage[1024] = {};
        decrypt(line, decryptedMessage, this->sessionKey);
        writeLine(this->plainTextLog, "Encrypted text received:");
        writeHex(this->plainTextLog, line, strlen(line));
        writeLine(this->plainTextLog, decryptedMessage);
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
    char *serverNonce;
    serverNonce = evbuffer_readln(input, &len, EVBUFFER_EOL_LF);

    writeLine(this->plainTextLog, "RECEIVED NONCE FROM SERVER:");
    writeHex(this->plainTextLog, serverNonce, strlen(serverNonce));

    // Encrypted message
    line = evbuffer_readln(input, &len, EVBUFFER_EOL_LF);

    writeLine(this->plainTextLog, "Encrypted received MESSAGE:");
    writeHex(this->plainTextLog, line, strlen(line));

    char decryptedMessage[30] = {};
    decrypt(line, decryptedMessage,this->sharedPrivateKey);
    free(line);

    writeLine(this->plainTextLog, "DECRYPTED MESSAGE:");
    writeHex(this->plainTextLog, decryptedMessage, strlen(decryptedMessage));

    char *sender = strtok(decryptedMessage, "\n");
    char *returnedNonce = strtok(NULL, "\n");
    char *serverDiffieHellmanValue = strtok(NULL, "\n");

    char output[100] = {};
    sprintf(output, "Sender: %s\n\nDH Val: %s\n", sender, serverDiffieHellmanValue);

    writeLine(this->plainTextLog, output);

    if(strcmp(sender, "Server") == 0)
    {
        writeLine(this->plainTextLog, "Message came from the server");

        if(are_nonces_equal(this->nonce, returnedNonce))
        {
            writeLine(this->plainTextLog, "Server returned correct Nonce");

            int clientDiffieHellmanVal = (int) pow(DIFFIE_HELLMAN_G, SECRET_A) % DIFFIE_HELLMAN_P;
            sprintf(output, "g^a mod p:: %d", clientDiffieHellmanVal);
            writeLine(this->plainTextLog, output);

            char messageToEncrypt[30] = {};

            sprintf(messageToEncrypt, "Client\n%s\n%d\n", serverNonce, clientDiffieHellmanVal);

            writeLine(this->plainTextLog, "Message to Encrypt:");
            writeHex(this->plainTextLog, messageToEncrypt, strlen(messageToEncrypt));

            char encryptedMessage[30] = {};
            encrypt(messageToEncrypt, encryptedMessage, this->sharedPrivateKey);

            writeLine(this->plainTextLog, "Encrypted Message:");
            writeHex(this->plainTextLog, encryptedMessage, strlen(encryptedMessage));

            client_send(this, encryptedMessage);


            int dhVal = atoi(serverDiffieHellmanValue);

            // This will be the key used for communication in the future
            int sessionKeyInt = (int) pow(dhVal, SECRET_A);
            char sessionKeyString[20] = {};
            sprintf(sessionKeyString, "%d", sessionKeyInt);

            this->sessionKey = key_init_new();
            this->sessionKey->data = get_md5_hash(sessionKeyString, strlen(sessionKeyString));
            this->sessionKey->length = strlen(this->sessionKey->data);

            writeLine(this->plainTextLog, "Session key:");
            writeHex(this->plainTextLog, this->sessionKey->data, this->sessionKey->length);

            this->authState = AUTH_STATE_AUTHENTICATED;
        }
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

        this->nonce = get_nonce();
        writeLine(this->plainTextLog,"Sending NONCE:");
        writeHex(this->plainTextLog, this->nonce, NONCE_SIZE);
        client_send_data(this, this->nonce, NONCE_SIZE);
    }
    else if (events & BEV_EVENT_ERROR)
    {
        gtk_button_set_label(GTK_BUTTON(this->statusButton), "Connect!");
        g_idle_remove_by_data(this);
    }
}

void client_send(Client* this, const char *msg)
{
    struct evbuffer *output = bufferevent_get_output(this->bev);
    if(this->sessionKey != NULL)
    {
        char encryptedMessage[1024] = {};
        encrypt((char *)msg, encryptedMessage, this->sessionKey);
        char line[1024] = {};
        sprintf(line, "Sending message '%s' as encrypted text:", msg );
        writeLine(this->plainTextLog, line);
        writeHex(this->plainTextLog, encryptedMessage, strlen(encryptedMessage));
        evbuffer_add_printf(output, "%s\n", encryptedMessage);
    }
    else
    {
        evbuffer_add_printf(output, "%s\n", msg);
    }
}

void client_send_data(Client *this, const void *data, size_t size)
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

    this->sessionKey = NULL;

    this->sharedPrivateKey = key_init_new();
    const char *keyText = gtk_entry_get_text(GTK_ENTRY(this->sharedKey));
    this->sharedPrivateKey->length = strlen(keyText);
    this->sharedPrivateKey->data = malloc(this->sharedPrivateKey->length);
    strcpy(this->sharedPrivateKey->data, keyText);

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