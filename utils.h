#ifndef UTILS_H_
#define UTILS_H_

#include <gtk/gtk.h>

void printHex(char *bytes, int len);
void writeHex(GtkWidget *textView, char *text, int length);
void writeLine(GtkWidget *textView, const char * text);

#endif