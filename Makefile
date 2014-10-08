all:
	gcc -Wall -g `pkg-config --cflags gtk+-3.0` -o main main.c server.c client.c utils.c -levent `pkg-config --libs gtk+-3.0`