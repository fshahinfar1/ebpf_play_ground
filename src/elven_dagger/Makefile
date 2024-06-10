JFLAGS = -g
JC = javac
.SUFFIXES: .java .class
.PHONY: default run

CLASSES = $(wildcard src/*.java)

default: $(CLASSES)
	$(JC) $(JFLAGS) -d ./build/ -cp ./ $(CLASSES)

clean:
	$(RM) ./build/
