
NAME?=go-peafowl

all:
	#@ if [ ! -d "peafowl_lib" ]; then git clone https://github.com/DanieleDeSensi/Peafowl.git peafowl_lib; fi;
	#@ if [ ! -f peafowl_lib/lib/libdpi.a ]; then make -C peafowl_lib; fi;
	
	go build -ldflags "-s -w"  -o example/$(NAME) example/*.go

debug:
	go build -o example/$(NAME) example/*.go

.PHONY: clean
clean:
	rm -fr $(NAME)