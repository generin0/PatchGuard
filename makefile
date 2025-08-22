CC = gcc
CFLAGS = -Wall -Wextra -O2
LDFLAGS = -lpsapi

SRCS = main.c crc_f_main.c
OBJS = $(SRCS:.c=.o)
TARGET = pe_protected_app

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean
