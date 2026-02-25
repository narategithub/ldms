CFLAGS = -ggdb3 -O0 -I/opt/ovis/include
LDFLAGS = -L/opt/ovis/lib -lldms

ALL = analyser app

all: $(ALL)

%: %.c
	$(CC) $< $(CFLAGS) $(LDFLAGS) -o $@
clean:
	rm -f $(ALL)
