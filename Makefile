.SUFFIXES: .cpp .o
CXX = g++
TARGET = pcap-test
OBJS = pkt_info_func.o main.o

$(TARGET): $(OBJS)
	$(CXX) -o $(TARGET) $(OBJS) -lpcap
	rm -f *.o

pkt_info_func.o: pkt_info_func.cpp
	$(CXX) -c -o pkt_info_func.o pkt_info_func.cpp

main.o: main.cpp
	$(CXX) -c -o main.o main.cpp

clean:
	rm -f pcap-test