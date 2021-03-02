CC := gcc
LDFLAGS := -lmosquitto -ljwt -lssl -lcrypto ../../../Sparkplug-master/client_libraries/c/lib/libsparkplug_b.a 
CFLAGS := -Wall -g
TARGET := runMe

SRCS := $(wildcard *.c)
OBJS := $(patsubst %.c,%.o,$(SRCS))

all: $(TARGET)
$(TARGET): $(OBJS)
	$(CC) -o $@ $^ ${LDFLAGS}
%.o: %.c
	$(CC) $(CFLAGS) -c $< -I../../lib
clean:
	rm -rf $(TARGET) *.o
	
.PHONY: all clean
