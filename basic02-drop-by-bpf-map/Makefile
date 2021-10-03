CC := clang

BPF_CFLAGS := -O2 -target bpf -Werror -Wall -c
CFLAGS := -g -Werror -Wall

EXECABLE = xdp-prog-user
BPFCODE = xdp-prog-kern

LIBS = -l:libbpf.a -lelf

.PHONY: clean $(BPFCODE:=.c)

clean:
	rm -f *.o $(EXECABLE)

$(BPFCODE:=.o): $(BPFCODE:=.c)
	$(CC) $(BPF_CFLAGS) $(BPFCODE:=.c) -o $(BPFCODE:=.o)

$(EXECABLE): $(BPFCODE:=.o)
	$(CC) $(CFLAGS) $(EXECABLE:=.c) -o $(EXECABLE) $(LIBS)

.DEFAULT_GOAL := $(EXECABLE)