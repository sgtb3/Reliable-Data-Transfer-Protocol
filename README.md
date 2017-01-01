###Contents

#####RDT_Protocol.java

- Abstract class that simulates a reliable data transfer protocol.
- Encapsulates a TCP_Packet object in the data field of a UDP datagram.
- Capable of handling buffer overflow attacks.
- Drops out-of-order datagrams.
- Uses TCP/IP/UDP checksum to check for packet corruption.
- Simulates GBN Protocol for packet loss.
- Calculates packet Round-Trip-Times.
- Has debugging functionality.
- Logs in-order, non-corrupt received packets.

#####RDT_Receiver.java

- Simulates a reliable receiver.
- Contains threads for sending and receiving datagrams simultaneously.

#####RDT_Sender.java

- Simulates a reliable sender.
- Contains threads for sending and receiving datagrams simultaneously.

#####TCP_Packet.java

- An abstraction of a TCP packet.
- Contains methods for calculating TCP/IP/UDP 16-bit one's complement checksum,
  encoding and decoding a byte array to and from a TCP_Packet object.

#####Timer.java

- An abstraction of a timer.
- Runs concurrent to Sender and Receiver as a separate thread.
- At any given time, timer is active for only one sent but not yet
  acknowledged datagram.
- Contains methods to calculate the sample, estimated, and deviation from estimate
  Round-Trip-Times.

#####Segment.java:

- An abstraction of a TCP segment containing data.
- Contains fields to track various segment properties (sent, ACKed, etc.)

#####Makefile

* `make` compiles the `.java` source files using the `javac` compiler.
* `make clean` will clean all auxiliary `.class` files.

#####Usage

	make
	java RDT_Receiver <filename> <log_filename> <sender_IP> <sender_port>
			      	  <listening_port> optional: <debug>
	java RDT_Sender   <filename> <log_filename> <receiver_IP> <receiver_port>
			      	  <listening_port> <windows size>
			      	  optional: <debug>

#####Example

	make
	recv.jpg stdout localhost 10988 10989 debug
	send.jpg sendLog.txt localhost 10989 10988
