CC = musl-gcc
LDFLAGS = -static

TARGET = tsune
SRCS = e.c

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

clean:
	rm -f $(TARGET)

.PHONY: all clean


