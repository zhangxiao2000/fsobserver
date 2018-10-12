CC = g++
CFLAGS  := -Wall -fPIC -g 

OBJS = ceph.o
BIN = fsobserver

all: $(BIN)

$(BIN): $(OBJS)
	g++ -g -o $(BIN) $(OBJS)

%.o : %.cpp
	$(CC) $(CFLAGS) -c $< -o $@ $(INC_DIR)


clean:
	rm -f $(BIN) $(OBJS)
