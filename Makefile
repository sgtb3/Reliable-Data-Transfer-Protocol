JFLAGS = -g
JC = javac

.SUFFIXES: .java .class

.java.class:
	$(JC) $(JFLAGS) $*.java

CLASSES = \
    RdtReceiver.java \
    RdtSender.java \

default: clean classes 

classes: $(CLASSES:.java=.class)

.PHONY: clean
clean:
	rm -f *.class
