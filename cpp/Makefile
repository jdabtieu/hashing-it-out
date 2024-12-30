OPTS_PRE = -O2 -std=c++17 -lcrypto
OPTS_ARG1 = -L/home/cs263/argon2/lib/x86_64-linux-gnu -I/home/cs263/argon2/include -largon2
OPTS_ARG2 = -L/home/jw/Desktop/argon2/lib/x86_64-linux-gnu -I/home/jw/Desktop/argon2/include -largon2
OPTS_POST = -lcrypt -march=native

all:
	g++ main.cpp base64.c -o bench $(OPTS_PRE) $(OPTS_ARG1) $(OPTS_POST)
	g++ hash_one.cpp base64.c -o hash_one $(OPTS_PRE) $(OPTS_ARG1) $(OPTS_POST)
two:
	g++ main.cpp base64.c -o bench $(OPTS_PRE) $(OPTS_ARG2) $(OPTS_POST)
	g++ hash_one.cpp base64.c -o hash_one $(OPTS_PRE) $(OPTS_ARG2) $(OPTS_POST)
debug:
	g++ main.cpp base64.c -o bench $(OPTS_PRE) $(OPTS_ARG2) $(OPTS_POST) -g -ggdb3
	g++ hash_one.cpp -o hash_one $(OPTS_PRE) $(OPTS_ARG1) $(OPTS_POST) -g -ggdb3
clean:
	rm -f bench hash_one
