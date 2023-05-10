# export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:../libjwt/libjwt/.libs
# export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:../../lib
# export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:../../../jansson-2.11/src/.libs

CC := gcc
LDFLAGS := -L../libjwt/libjwt/.libs -ljwt -lssl -lcrypto ../../../Sparkplug-master/client_libraries/c/lib/libsparkplug_b.a -lmosquitto
CFLAGS := -Wall -Wno-unused-variable -Wno-unused-but-set-variable -Wno-unused-function -I../../lib -I../libjwt/include
TARGET := runMe

SRCS := $(wildcard *.c)
OBJS := $(patsubst %.c,%.o,$(SRCS))

all: $(TARGET)
$(TARGET): $(OBJS)
	$(CC) -o $@ $^ ${LDFLAGS}
%.o: %.c
	$(CC) $(CFLAGS) -c $<
clean:
	rm -rf $(TARGET) *.o
	
.PHONY: all clean
