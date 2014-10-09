all:
	gcc -Wall -g `pkg-config --cflags gtk+-3.0 libevent` -o main main.c server.c client.c utils.c `pkg-config --libs gtk+-3.0 libevent`