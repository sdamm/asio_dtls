# DTLS support for ASIO using C++11

## Introduction
ASIO::DTLS is an extension to ASIO([think-async.com](https://think-async.com)). It provides encryption for
Datagram based transports. The encryption is based on DTLS([rfc6347](https://tools.ietf.org/html/rfc6347)) using the OpenSSL([openssl.org](https://www.openssl.org/)) libraries.

ASIO::DTLS offers dtls\_listen functionality which can be used to prevent certain DOS attacks
against the Server side (see https://tools.ietf.org/html/rfc4347#section-4.2.1).

### Differences between Datagram and Stream based Communication
There are three main differences from a programmer's standpoint between
the Stream based and Datagram based Communication approaches:

* With **Stream** based communication all data is treated as a Stream
so the data of multiple send operations is concatenated and
can be received with a single receive operation, as if it was
sent by one operation. With Datagram based communication a
send operation sends exactly one Datagram and the receiving
side a receive operation receives exactly one Datagram, if the
Buffer Size on the receiving side was too small to hold the
complete Datagram the rest of the Datagram is typically discarded.

* Streams guarantee that the Data is received **in order** where
Datagrams might be received in a different order than they were sent.

* Typically, stream based approaches try to make sure the data is delivered
and have strategies for **retransmission**, ... to make sure no data is lost.
Datagram based communication generally does not have such a guarantee.

DTLS offers encryption for Datagram based communication and must
therefore allow Datagrams to be lost or received in wrong order.
It provides the same Datagram semantics, so lost Datagrams will
not be resend and out of order Datagrams are still out of order
after decryption.

With Stream based protocols the connection establishment does
validate (indirectly) that the other end is listening on the sender endpoint.
Which as a side effect reduces the possibilities for spoofing attacks,
which might be used for Denial-Of-Service/amplifier attacks against DTLS
servers (see [rfc6347 4.2.1](https://tools.ietf.org/html/rfc6347#section-4.2.1) for details).


### Differences between asio::ssl::stream and asio\_dtls
To account for the Datagram semantic several changes had to be made:
* To reflect the Datagram semantic the interface uses the same semantic for
sending and receiving as udp i.e.
  * send instead of write\_some
  * async\_send instead of async\_write\_some
  * ...

* `set_mtu`
While the datagram semantics would simply try to send all data provided to a
send call in one Datagram and fail if the Datagram is too big there is one
exception during the Handshake, where DTLS will split the handshake data
akkording to the mtu set here. Please note, that split handshakes do
not work together with the stateless Cookie exchange so for udp it
makes sense to set this value high and let the ip layer handle the splitting.
(The default value is set to do this).
 
* Cookies
asio\_dtls supports dtls Cookies through setting a Cookie generate and verify
callback on the server side. These are called whenever the Implementation
needs to generate or verify a Cookie. A Cookie should be specific to a client
endpoint to fulfill it's purpose.

* `dtls_context` instead of a ssl::context
A `dtls_context` allows to use methods like `dtls_client` which a normal `ssl::context`
does not. A `dtls_context` does not allow stream based methods like `tlsv12_server`.


## Dependencies
* Asio (tested with 1.13.0)
* OpenSSL > 1.0.2 or
* OpenSSL > 1.1.0 for correct dtls\_listen support
* cmake >= 3.2

## Work in Progress
This library is not finished and parts of the Code are copies from Files of ASIO.
The structure and some of the files might still change.
