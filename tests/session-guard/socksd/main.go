// Мини SOCKS5-сервер для стенда hev: CONNECT и UDP ASSOCIATE.
// CONNECT: порт 19 - бесконечный поток (chargen), порт 9 - discard, иначе echo.
// UDP: эхо; если payload начинается с "SHORT" - дополнительно шлёт клиенту датаграмму из 2 байт,
// если с "EMPTY" - датаграмму нулевой длины.
package main

import (
	"encoding/binary"
	"flag"
	"io"
	"log"
	"net"
	"sync/atomic"
	"time"
)

var udpShortSent atomic.Int64

func main() {
	addr := flag.String("l", "127.0.0.1:31080", "listen")
	flag.Parse()
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("socksd on %s", *addr)
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go handle(c)
	}
}

func readAddr(r io.Reader) (host []byte, port uint16, raw []byte, err error) {
	var atyp [1]byte
	if _, err = io.ReadFull(r, atyp[:]); err != nil {
		return
	}
	raw = append(raw, atyp[0])
	var l int
	switch atyp[0] {
	case 1:
		l = 4
	case 4:
		l = 16
	case 3:
		var n [1]byte
		if _, err = io.ReadFull(r, n[:]); err != nil {
			return
		}
		raw = append(raw, n[0])
		l = int(n[0])
	}
	b := make([]byte, l+2)
	if _, err = io.ReadFull(r, b); err != nil {
		return
	}
	raw = append(raw, b...)
	host = b[:l]
	port = binary.BigEndian.Uint16(b[l:])
	return
}

func handle(c net.Conn) {
	defer c.Close()
	var hdr [2]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		return
	}
	methods := make([]byte, hdr[1])
	io.ReadFull(c, methods)
	c.Write([]byte{5, 0})
	var req [3]byte
	if _, err := io.ReadFull(c, req[:]); err != nil {
		return
	}
	_, port, _, err := readAddr(c)
	if err != nil {
		return
	}
	switch req[1] {
	case 1: // CONNECT
		c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
		switch port {
		case 19:
			buf := make([]byte, 32*1024)
			for i := range buf {
				buf[i] = byte('a' + i%26)
			}
			for {
				if _, err := c.Write(buf); err != nil {
					return
				}
			}
		case 9:
			io.Copy(io.Discard, c)
		default:
			io.Copy(c, c)
		}
	case 3: // UDP ASSOCIATE
		pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			return
		}
		defer pc.Close()
		la := pc.LocalAddr().(*net.UDPAddr)
		rep := []byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0}
		binary.BigEndian.PutUint16(rep[8:], uint16(la.Port))
		c.Write(rep)
		go func() {
			buf := make([]byte, 65536)
			for {
				pc.SetReadDeadline(time.Now().Add(120 * time.Second))
				n, from, err := pc.ReadFromUDP(buf)
				if err != nil {
					return
				}
				p := buf[:n]
				if len(p) < 4 {
					continue
				}
				// RSV RSV FRAG ATYP ...
				r := bytesReader(p[3:])
				_, _, raw, err := readAddr(r)
				if err != nil {
					continue
				}
				payload := p[3+len(raw):]
				out := append([]byte{0, 0, 0}, raw...)
				out = append(out, payload...)
				pc.WriteToUDP(out, from)
				if len(payload) >= 5 && string(payload[:5]) == "SHORT" {
					pc.WriteToUDP([]byte{0, 0}, from)
					udpShortSent.Add(1)
					log.Printf("sent 2-byte datagram to %v", from)
				}
				if len(payload) >= 5 && string(payload[:5]) == "EMPTY" {
					pc.WriteToUDP([]byte{}, from)
					log.Printf("sent 0-byte datagram to %v", from)
				}
			}
		}()
		io.Copy(io.Discard, c)
	}
}

type br struct {
	b []byte
}

func bytesReader(b []byte) *br { return &br{b} }
func (r *br) Read(p []byte) (int, error) {
	if len(r.b) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.b)
	r.b = r.b[n:]
	return n, nil
}
