CC = g++
# CXXFLAGS = -Wall -std=c++20 -ggdb -DDEBUG
CXXFLAGS = -Wall -std=c++20 -O1 -fno-exceptions -fno-rtti
LDFLAGS = -libverbs -fno-exceptions -fno-rtti
HEADERS = $(wildcard *.h)
OBJECTS = weak.o rdtm.o

rdtma: $(OBJECTS)
	$(CC) -o $@ $^ $(LDFLAGS)
	strip $@

%.o: %.cc $(HEADERS)
	$(CC) -c -o $@ $< $(CXXFLAGS)

weak.o: weak-magic.inl

weak-magic.inl: genprog.py
	python3 genprog.py > weak-magic.inl

clean:
	rm -f rdtma $(OBJECTS)

.PHONY: clean
