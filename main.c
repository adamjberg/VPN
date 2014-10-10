#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <gtk/gtk.h>

#include "utils.h"
#include "client.h"
#include "server.h"

#define WINDOW_WIDTH 200
#define WINDOW_HEIGHT 600

#define CLIENT_ID 0
#define SERVER_ID 1

gboolean isServer = FALSE;

GtkWidget *window;
GtkWidget *vBox;
GtkWidget *scrolledCipherWindow;
GtkWidget *scrolledPlaintextWindow;
GtkWidget *serverDetailsHBox;
GtkWidget *clientServerModeHBox;
GtkWidget *modeLabel;
GtkWidget *modeComboBox;
GtkWidget *messageHBox;
GtkWidget *messageLabel;
GtkWidget *messageEntry;
GtkWidget *messageSendButton;
GtkWidget *cipherTextLog;
GtkWidget *plainTextLog;
GtkWidget *cipherTextLogLabel;
GtkWidget *plainTextLogLabel;
GtkWidget *serverName;
GtkWidget *serverNameLabel;
GtkWidget *portNumber;
GtkWidget *portNumberLabel;
GtkWidget *sharedKey;
GtkWidget *sharedKeyLabel;
GtkWidget *serverStatusButton;
GtkWidget *clientStatusButton;

Server *server;
Client *client;

typedef struct SendButtonData
{
    GtkWidget *entry;
    GtkWidget *messageLog;
} SendButtonData;

void initServer()
{
    server = server_init_new(serverStatusButton, plainTextLog, cipherTextLog, portNumber, serverName, sharedKey);
}

void closeServer()
{
    server_free(server);
}

void initClient()
{
    client = client_init_new(clientStatusButton, plainTextLog, cipherTextLog, portNumber, serverName, sharedKey);
}

void closeClient()
{
    client_free(client);
}

void onModeChanged(GtkWidget *widget, gpointer data)
{
    int id = gtk_combo_box_get_active(GTK_COMBO_BOX(widget));

    if (id == CLIENT_ID)
    {
        gtk_widget_hide(serverStatusButton);
        gtk_widget_show(clientStatusButton);
        isServer = FALSE;
    }
    else
    {
        gtk_widget_hide(clientStatusButton);
        gtk_widget_show(serverStatusButton);
        isServer = TRUE;
    }
}

void onServerStatusChanged(GtkWidget *widget, gpointer data)
{
    if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(widget)))
    {
        initServer();
    }
    else
    {
        closeServer();
    }
}

void onClientStatusChanged(GtkWidget *widget, gpointer data)
{
    if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(widget)))
    {
        initClient();
    }
    else
    {
        closeClient();
    }
}

void onSendButtonClicked(GtkWidget *widget, gpointer data)
{
    SendButtonData *sbData = data;
    const char *text = gtk_entry_get_text(GTK_ENTRY(sbData->entry));
    if (isServer)
    {
        writeLine(sbData->messageLog, "Server:");
    }
    else
    {
        writeLine(sbData->messageLog, "Client: ");
    }
    writeLine(sbData->messageLog, text);
    if(client != NULL)
    {
        client_send(client, text);
    }
    else if(server != NULL)
    {
        server_send(server, text);
    }
}

void initGUI(int argc, char *argv[])
{
    gtk_init (&argc, &argv);

    window = gtk_window_new (GTK_WINDOW_TOPLEVEL);
    gtk_window_set_default_size(GTK_WINDOW (window), WINDOW_WIDTH, WINDOW_HEIGHT);
    gtk_window_set_title (GTK_WINDOW (window), "EECE 412 VPN");

    g_signal_connect (window, "destroy", G_CALLBACK (gtk_main_quit), NULL);

    vBox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 1);
    clientServerModeHBox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 1);
    messageHBox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 1);
    serverDetailsHBox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 1);

    modeLabel = gtk_label_new("Mode:");

    modeComboBox = gtk_combo_box_text_new();
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(modeComboBox), "Client");
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(modeComboBox), "Server");
    gtk_combo_box_set_active(GTK_COMBO_BOX(modeComboBox), 0);

    messageLabel = gtk_label_new("Message:");
    messageEntry = gtk_entry_new();

    serverName = gtk_entry_new();
    gtk_entry_set_text(GTK_ENTRY(serverName), "127.0.0.1");
    gtk_entry_set_max_length(GTK_ENTRY(serverName), 15);
    serverNameLabel = gtk_label_new("Server name:");
    serverStatusButton = gtk_toggle_button_new_with_label("Start!");
    clientStatusButton = gtk_toggle_button_new_with_label("Connect!");

    portNumber = gtk_entry_new();
    gtk_entry_set_text(GTK_ENTRY(portNumber), "12000");
    gtk_entry_set_max_length(GTK_ENTRY(portNumber), 5);
    portNumberLabel = gtk_label_new("Port:");

    sharedKey = gtk_entry_new();
    sharedKeyLabel = gtk_label_new("Shared key:");

    messageSendButton = gtk_button_new_with_label("Send");

    scrolledCipherWindow = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW(scrolledCipherWindow), GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_scrolled_window_set_min_content_height (GTK_SCROLLED_WINDOW(scrolledCipherWindow), 200);

    scrolledPlaintextWindow = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW(scrolledPlaintextWindow), GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_scrolled_window_set_min_content_height (GTK_SCROLLED_WINDOW(scrolledPlaintextWindow), 200);

    cipherTextLog = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(cipherTextLog), FALSE);
    gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(cipherTextLog), FALSE);

    cipherTextLogLabel = gtk_label_new("Cipher text:");

    plainTextLog = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(plainTextLog), FALSE);
    gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(plainTextLog), FALSE);

    plainTextLogLabel = gtk_label_new("Plain text:");

    // SIGNALS
    g_signal_connect (modeComboBox, "changed", G_CALLBACK(onModeChanged), NULL);
    SendButtonData *data = malloc(sizeof(*data));
    data->entry = messageEntry;
    data->messageLog = cipherTextLog;
    g_signal_connect (messageSendButton, "clicked", G_CALLBACK(onSendButtonClicked), data);
    g_signal_connect(serverStatusButton, "toggled", G_CALLBACK(onServerStatusChanged), NULL);
    g_signal_connect(clientStatusButton, "toggled", G_CALLBACK(onClientStatusChanged), NULL);

    gtk_container_add (GTK_CONTAINER(window), vBox);

    gtk_box_pack_start (GTK_BOX(clientServerModeHBox), modeLabel, FALSE, TRUE, 1);
    gtk_box_pack_start (GTK_BOX(clientServerModeHBox), modeComboBox, TRUE, TRUE, 1);

    gtk_box_pack_start (GTK_BOX(serverDetailsHBox), serverNameLabel, FALSE, FALSE, 1);
    gtk_box_pack_start (GTK_BOX(serverDetailsHBox), serverName, TRUE, TRUE, 1);
    gtk_box_pack_start (GTK_BOX(serverDetailsHBox), portNumberLabel, FALSE, FALSE, 1);
    gtk_box_pack_start (GTK_BOX(serverDetailsHBox), portNumber, TRUE, TRUE, 1);
    gtk_box_pack_start (GTK_BOX(serverDetailsHBox), sharedKeyLabel, FALSE, FALSE, 1);
    gtk_box_pack_start (GTK_BOX(serverDetailsHBox), sharedKey, TRUE, TRUE, 1);
    gtk_box_pack_start (GTK_BOX(serverDetailsHBox), clientStatusButton, FALSE, FALSE, 1);
    gtk_box_pack_start (GTK_BOX(serverDetailsHBox), serverStatusButton, FALSE, FALSE, 1);


    gtk_box_pack_start (GTK_BOX(messageHBox), messageLabel, FALSE, FALSE, 1);
    gtk_box_pack_start (GTK_BOX(messageHBox), messageEntry, TRUE, TRUE, 1);
    gtk_box_pack_start (GTK_BOX(messageHBox), messageSendButton, FALSE, FALSE, 1);

    gtk_container_add (GTK_CONTAINER(vBox), clientServerModeHBox);
    gtk_container_add (GTK_CONTAINER(vBox), serverDetailsHBox);
    gtk_container_add (GTK_CONTAINER(vBox), messageHBox);

    gtk_container_add (GTK_CONTAINER(vBox), cipherTextLogLabel);
    gtk_container_add(GTK_CONTAINER(scrolledCipherWindow), cipherTextLog);
    gtk_container_add (GTK_CONTAINER(vBox), scrolledCipherWindow);

    gtk_container_add (GTK_CONTAINER(vBox), plainTextLogLabel);
    gtk_container_add(GTK_CONTAINER(scrolledPlaintextWindow), plainTextLog);
    gtk_container_add (GTK_CONTAINER(vBox), scrolledPlaintextWindow);

    gtk_widget_show_all (window);

    gtk_widget_hide(serverStatusButton);
}

int main (int argc, char *argv[])
{
    initGUI(argc, argv);

    gtk_main ();

    return 0;
}