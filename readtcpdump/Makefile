CC = g++
CFLAGS  := -Wall -fPIC -fpermissive -g

OBJS1 = dynaceph.o sniffex.o parsepacket.o
BIN1 = fsobserver

OBJS2 = dynaceph.o readtcpdump.o parsepacket.o
BIN2 = readtcpdump

all: $(BIN1) $(BIN2)

$(BIN1): $(OBJS1)
	g++ -g -o $(BIN1) $(OBJS1) -lpcap

$(BIN2): $(OBJS2)
	g++ -g -o $(BIN2) $(OBJS2) -lpcap

%.o : %.cpp
	$(CC) $(CFLAGS) -c $< -o $@ $(INC_DIR)


clean:
	rm -f $(BIN1) $(OBJS1) $(BIN2) $(OBJS2)
