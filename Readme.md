# DTLS support for ASIO using C++11

## Introduction
ASIO::DTLS is a extension to ASIO([think-async.com](https://think-async.com)) allowing
DTLS([rfc6347](https://tools.ietf.org/html/rfc6347)) which provides encryption over
Datagram based transports. The encryption is done using OpenSSL([openssl.org](https://www.openssl.org/)).

The library offers dtls\_listen functionality which can be used to prevent certain DOS attacks
against the Server side (see https://tools.ietf.org/html/rfc4347#section-4.2.1).

## Dependencies
* Asio (tested with 1.12.0)
* OpenSSL > 1.0.2 or
* OpenSSL > 1.1.0 for correct dtls\_listen support
* cmake >= 3.2
