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

/**
 * Helper function to send message to the Client
 */ 
void server_send(Server *this, const char *msg)
{
    struct evbuffer *output = bufferevent_get_output(this->bev);
    if(this->sessionKey != NULL)
    {
        char encryptedMessage[1024] = {};
        char buf[1024] = {};
        encrypt_with_key((char *)msg, encryptedMessage, this->sessionKey);
        sprintf(buf, "Server: %s", msg);
        writeLine(this->plainTextLog, buf);
        writeHex(this->cipherTextLog, "Server: ", encryptedMessage, strlen(encryptedMessage));
        evbuffer_add_printf(output, "%s\r\n", encryptedMessage);
    }
    else
    {
        evbuffer_add_printf(output, "%s\r\n", msg);
    }
}

/**
 * Helper function to send data (this may not be valid ASCII) to the Client
 */ 
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

/**
 * Callback for when there is data in the buffer
 * Calls different functions based on the authentication status
*/
void server_readcb(struct bufferevent *bev, void *ctx)
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
    while ((line = evbuffer_readln(input, &n, EVBUFFER_EOL_CRLF_STRICT))) {
        char decryptedMessage[1024] = {};
        char buf[1024] = {};
        decrypt_with_key(line, decryptedMessage, this->sessionKey);
        writeHex(this->cipherTextLog, "Client: ", line, strlen(line));
        sprintf(buf, "Client: %s", decryptedMessage);
        writeLine(this->plainTextLog, buf);
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
    line = evbuffer_readln(input, &len, EVBUFFER_EOL_CRLF_STRICT);

    writeHex(this->authenticationTextLog, "Client: Encrypted message ", line, strlen(line));

    char decryptedMessage[1024] = {};
    decrypt_with_key(line, decryptedMessage, this->sharedPrivateKey);

    char *sender = strtok(decryptedMessage, "\r\n");
    char *returnedNonce = strtok(NULL, "\r\n");
    char *clientDiffieHellmanValue = strtok(NULL, "\r\n");

    char output[1024] = {};
    sprintf(output, "Client: I am %s.\nClient: Diffie-Hellman Value is %s.", sender, clientDiffieHellmanValue);
    writeLine(this->authenticationTextLog, output);
    writeHex(this->authenticationTextLog, "Client: Your nonce was ", returnedNonce, NONCE_SIZE);

    if(strcmp(sender, "Client") == 0)
    {
        if(are_nonce_bytes_equal(this->nonce->bytes, returnedNonce))
        {
            int dhVal = atoi(clientDiffieHellmanValue);

            // This will be the key used for communication in the future
            int sessionKeyInt = (int) pow(dhVal, this->secretB) % DIFFIE_HELLMAN_P;
            this->secretB = 0;
            char sessionKeyString[20] = {};
            sprintf(sessionKeyString, "%d", sessionKeyInt);

            this->sessionKey = key_init_new();
            this->sessionKey->data = get_md5_hash(sessionKeyString, strlen(sessionKeyString));
            this->sessionKey->length = strlen(this->sessionKey->data);

            writeHex(this->authenticationTextLog, "Server: Calculated session key: ", this->sessionKey->data, this->sessionKey->length);

            this->authState = AUTH_STATE_AUTHENTICATED;
        }
    }
}

// The client should be sending us their public key Ra
void serverReadStateNoAuthentication(Server *this)
{
    char outputBuf[1024];
    // Rb nonce
    this->nonce = get_nonce();

    // Ra nonce
    char clientNonce[NONCE_SIZE] = {};
    bufferevent_read(this->bev, clientNonce, NONCE_SIZE);

    writeHex(this->authenticationTextLog, "Client: My nonce is ", clientNonce, NONCE_SIZE);
    
    sprintf(outputBuf, "Server: My nonce is %s", this->nonce->hex);
    writeLine(this->authenticationTextLog, outputBuf);

    this->secretB = get_random_int(DIFFIE_HELLMAN_EXP_RANGE);
    int diffieHellmanVal = (int) pow(DIFFIE_HELLMAN_G, this->secretB) % DIFFIE_HELLMAN_P;
    char output[1024] = {};
    sprintf(output, "Server: g^b mod p: %d with b: %d", diffieHellmanVal, this->secretB);
    writeLine(this->authenticationTextLog, output);

    char messageToEncrypt[1024] = {};
    sprintf(messageToEncrypt, "Server\r\n%s\r\n%d", clientNonce, diffieHellmanVal);

    writeHex(this->authenticationTextLog, "Server: My unencrypted message is ", messageToEncrypt, strlen(messageToEncrypt));

    char encryptedMessage[1024] = {};
    encrypt_with_key(messageToEncrypt, encryptedMessage, this->sharedPrivateKey);

    writeHex(this->authenticationTextLog, "Server: My encrypted message is ", encryptedMessage, strlen(encryptedMessage));

    char fullMessage[1024] = {};
    int fullMessageLength = sprintf(fullMessage, "%s\r\n%s\r\n", this->nonce->bytes, encryptedMessage);

    writeHex(this->authenticationTextLog, "Server: Sending data ", fullMessage, fullMessageLength);

    server_send_data(this, fullMessage, fullMessageLength);

    // We have proven to the client who we are
    // Now we must check whether the client is who we think it is
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

/**
 * Callback to accept a connection
 * Here we create a new socket to handle further communications
 */
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

/**
 * Process any events in the event queue
*/
gboolean server_event_loop(Server* server)
{
    if(server != NULL && server->eventBase != NULL)
    {
        event_base_loop(server->eventBase, EVLOOP_NONBLOCK);
        return TRUE;
    }
    return FALSE;
}

/**
 * Initializes the Server
 * Opens a TCP socket
 * Sets up events to work asynchronously
 */
struct Server* server_init_new(
    GtkWidget *statusButton,
    GtkWidget *plainTextLog,
    GtkWidget *cipherTextLog,
    GtkWidget *portNumber,
    GtkWidget *serverName,
    GtkWidget *sharedKey,
    GtkWidget *authenticationTextLog
)
{
    Server *this = malloc(sizeof(Server));

    this->plainTextLog = plainTextLog;
    this->cipherTextLog = cipherTextLog;
    this->authenticationTextLog = authenticationTextLog;
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

    gtk_button_set_label(GTK_BUTTON(this->statusButton), "Running");

    return this;
}

/**
 * Free up data allocated in Server
 */
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