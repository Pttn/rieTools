CXX    = g++
CFLAGS = -Wall -Wextra -std=gnu++11
LIBS   = -lcrypto -lgmpxx -lgmp

TOOLS  = keysGen constellationsGen constellationCheck blockHeaderDecode

all: $(TOOLS)

blockHeaderDecode: blockHeaderDecode.cpp rieTools.cpp rieTools.h
	$(CXX) $(CFLAGS) -o blockHeaderDecode $^ $(LIBS)

blockHeaderDecode.o: blockHeaderDecode.cpp
	$(CXX) $(CFLAGS) -c -o blockHeaderDecode.o blockHeaderDecode.cpp

constellationCheck: constellationCheck.cpp rieTools.cpp rieTools.h
	$(CXX) $(CFLAGS) -o constellationCheck $^ $(LIBS)

constellationCheck.o: constellationCheck.cpp
	$(CXX) $(CFLAGS) -c -o constellationCheck.o constellationCheck.cpp

constellationsGen: constellationsGen.cpp rieTools.cpp rieTools.h
	$(CXX) $(CFLAGS) -o constellationsGen $^ $(LIBS)

constellationsGen.o: constellationsGen.cpp
	$(CXX) $(CFLAGS) -c -o constellationsGen.o constellationsGen.cpp

keysGen: keysGen.cpp rieTools.cpp rieTools.h
	$(CXX) $(CFLAGS) -o keysGen $^ $(LIBS)

keysGen.o: keysGen.cpp
	$(CXX) $(CFLAGS) -c -o keysGen.o keysGen.cpp

rieTools.o: rieTools.cpp rieTools.h
	$(CXX) $(CFLAGS) -c -o rieTools.o rieTools.cpp

clean:
	rm -rf $(TOOLS) *.o
