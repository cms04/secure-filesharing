CC = gcc
CFLAGS = -Wall -std=gnu11 -g -lssl -lcrypto
OUTPUT = securefilesharing

$(OUTPUT): objects
	$(CC) -o $(OUTPUT) obj/*.o $(CFLAGS)

objects: src/main.c src/server.c src/server.h src/client.c src/client.h src/functions.c src/functions.h
	mkdir -p obj
	$(CC) -c src/main.c -o obj/main.o $(CFLAGS)
	$(CC) -c src/client.c -o obj/client.o $(CFLAGS)
	$(CC) -c src/server.c -o obj/server.o $(CFLAGS)
	$(CC) -c src/functions.c -o obj/functions.o $(CFLAGS)

clean:
	rm -rf obj
	rm -f $(OUTPUT)
