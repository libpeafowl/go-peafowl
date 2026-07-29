
NAME?=go-peafowl

all:
	@ if [ ! -d "./include/peafowl_lib" ]; then git clone https://github.com/DanieleDeSensi/Peafowl.git ./include/peafowl_lib; fi;
	@ if [ ! -f  ./include/peafowl_lib/build/src/libpeafowl.so ]; then cd ./include/peafowl_lib && mkdir build && cd build && cmake ../ && make; fi;
	@ if [ ! -d  peafowl ]; then mkdir peafowl; fi;
	@ if [ -f  ./include/peafowl_lib/build/src/libpeafowl.so ]; then cp ./include/peafowl_lib/build/src/libpeafowl.so peafowl; fi;
	@ if [ -f  ./include/peafowl_lib/include/peafowl/peafowl.h ]; then cp -r ./include/peafowl_lib/include/peafowl/* peafowl; fi;

	
	go build -ldflags "-s -w"  -o example/$(NAME) example/*.go

debug:
	go build -o example/$(NAME) example/*.go

.PHONY: clean
clean:
	rm -fr $(NAME)