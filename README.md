### Contents

##### RdtProtocol.java

- Abstract class that simulates a reliable data transfer protocol.
- Encapsulates a TcpPacket object in the data field of a UDP datagram.
- Capable of handling buffer overflow attacks.
- Drops out-of-order datagrams.
- Uses TCP/IP/UDP checksum to check for packet corruption.
- Simulates GBN Protocol for packet loss.
- Calculates packet Round-Trip-Times.
- Has debugging functionality.
- Logs in-order, non-corrupt received packets.

##### RdtReceiver.java

- Simulates a reliable receiver.
- Contains threads for sending and receiving datagrams simultaneously.

##### RdtSender.java

- Simulates a reliable sender.
- Contains threads for sending and receiving datagrams simultaneously.

##### TcpPacket.java

- An abstraction of a TCP packet.
- Contains methods for calculating TCP/IP/UDP 16-bit one's complement checksum,
  encoding and decoding a byte array to and from a TcpPacket object.

##### Timer.java

- An abstraction of a timer.
- Runs concurrent to Sender and Receiver as a separate thread.
- At any given time, timer is active for only one sent but not yet
  acknowledged datagram.
- Contains methods to calculate the sample, estimated, and deviation from estimate
  Round-Trip-Times.

##### Segment.java:

- An abstraction of a TCP segment containing data.
- Contains fields to track various segment properties (sent, ACKed, etc.)

##### Makefile

- `make` compiles the `.java` source files using the `javac` compiler.
- `make clean` will clean all auxiliary `.class` files.

##### Usage

	make
	java RdtReceiver <filename> <log_filename> <sender_IP> <sender_port>
			      	  <listening_port> optional: <debug>
	java RdtSender   <filename> <log_filename> <receiver_IP> <receiver_port>
			      	  <listening_port> <window_size>
			      	  optional: <debug>
			      	  
- `sender_port` and `receiver_port` must be larger than well-known ports.
- `window_size` size must be under 32768.
- `log_filename` can optionally be set to `stdout`. 

##### Example

	make
	java RdtReceiver recv.jpg stdout localhost 10988 10989 debug
	java RdtSender send.jpg sendLog.txt localhost 10989 10988 32767 debug

##### Known Bugs
* Currently, sender must set the debug flag in order for file transfer to 
  work properly.
