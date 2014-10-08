#include <gtk/gtk.h>
#include <string.h>
#include <stdlib.h>

void writeLine(GtkWidget *textView, const char *text)
{
    GtkTextIter iter;
    GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(textView));
    gtk_text_buffer_get_end_iter(buffer, &iter);
    gtk_text_buffer_insert(buffer, &iter, text, strlen(text));
    gtk_text_buffer_insert(buffer, &iter, "\n", strlen("\n"));
}