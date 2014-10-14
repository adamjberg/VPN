#ifndef UTILS_H_
#define UTILS_H_

#include <gtk/gtk.h>

void getHex(char *bytes, char *hex, int len);
void writeHex(GtkWidget *textView, char *prefixText, char *textAsHex, int length);
void writeLine(GtkWidget *textView, const char * text);

#endif