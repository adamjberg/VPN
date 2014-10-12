all:
	gcc -Wall -g `pkg-config --cflags gtk+-3.0 libevent openssl` -o main main.c server.c client.c utils.c crypto.c `pkg-config --libs gtk+-3.0 libevent openssl` -lm