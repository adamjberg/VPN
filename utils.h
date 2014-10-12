#ifndef UTILS_H_
#define UTILS_H_

#include <gtk/gtk.h>

void printHex(unsigned char *bytes, int len);
void writeHex(GtkWidget *textView, unsigned char *text, int length);
void writeLine(GtkWidget *textView, const char * text);

#endif