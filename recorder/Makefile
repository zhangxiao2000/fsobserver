CC = g++
CFLAGS  := -Wall -fPIC -fpermissive -g 

OBJS = dynaceph.o sniffex.o
BIN = fsobserver

all: $(BIN)

$(BIN): $(OBJS)
	g++ -g -o $(BIN) $(OBJS) -lpcap

%.o : %.cpp
	$(CC) $(CFLAGS) -c $< -o $@ $(INC_DIR)


clean:
	rm -f $(BIN) $(OBJS)
