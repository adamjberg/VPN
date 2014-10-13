#include <gtk/gtk.h>
#include <string.h>
#include <stdlib.h>

void printHex(char *bytes, int len)
{
    int i;
    for( i = 0; i < len; i++)
    {
        printf("%02X", bytes[i]);
    }
    printf("\n");
}

void writeHex(GtkWidget *textView, char *text, int length)
{
    char outText[length * 2 + 1];
    GtkTextIter iter;
    GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(textView));
    gtk_text_buffer_get_end_iter(buffer, &iter);

    int i;
    for(i = 0; i<length; i++){
        sprintf(outText+i*2, "%02X", text[i]);
    }
    sprintf(outText+i*2, "\n");
    gtk_text_buffer_insert(buffer, &iter, outText, strlen(outText));
}

void writeLine(GtkWidget *textView, const char *text)
{
    GtkTextIter iter;
    GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(textView));
    gtk_text_buffer_get_end_iter(buffer, &iter);
    gtk_text_buffer_insert(buffer, &iter, text, strlen(text));
    gtk_text_buffer_insert(buffer, &iter, "\n", strlen("\n"));
}