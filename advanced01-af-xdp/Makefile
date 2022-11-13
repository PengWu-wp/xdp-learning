CC := clang

BPF_CFLAGS := -g -O2 -target bpf -Werror -Wall -c -I../libbpf/include/uapi/
CFLAGS := -g -Werror -Wall -I../libbpf/include/uapi/

EXECABLE = af_xdp_user
BPFCODE = af_xdp_kern

LIBS = -l:libbpf.a -lelf -lpthread -lz

.PHONY: clean $(BPFCODE:=.c)

clean:
	rm -f *.o $(EXECABLE)

$(BPFCODE:=.o): $(BPFCODE:=.c)
	$(CC) $(BPF_CFLAGS) $(BPFCODE:=.c) -o $(BPFCODE:=.o)

$(EXECABLE): $(BPFCODE:=.o)
	$(CC) $(CFLAGS) $(EXECABLE:=.c) -o $(EXECABLE) $(LIBS)

.DEFAULT_GOAL := $(EXECABLE)
