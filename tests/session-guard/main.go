// Смоук hev кита (срез macosx arm64): gVisor netstack <-> socketpair (формат utun) <-> hev <-> socksd.
// Часть 1 - проверки r8: relieve, гонка relieve с остановкой.
// Часть 2 - бюджет сессий: G1 одна таблица max-session-count, у потолка новая сессия вытесняет давнее
// всех активную и не получает отказ; G2 TCP в той же таблице; G3 защита evict-protect-idle и её конец;
// G4 защищённые держат не больше половины таблицы; G7 молодой поток с ответом держится 2 с; G5 колбэк
// памяти (HOLD вытесняет сессию своего типа вместо отказа, CLOSED отказывает, гистерезис, типы
// колбэка); G6 повторное чтение конфига на перезапуске; K5, H5, K6, W4 правки по ревью колбэка.
// Часть 3 - пул DNS (0009, 0011): D - пул мимо полной таблицы, HOLD и CLOSED, адреса из списка и мимо
// него, вытеснение и отказ в полном пуле, свой таймаут, старый размер статистики; D6 - запрос сверх
// полного пула идёт обычным путём UDP; O - такой запрос живёт по таймауту пула и без защиты; F -
// правки по ревью пула.
// Число сессий в части 1 читается из строки лога hev "relieve ... udp U tcp T of N", в частях 2 и 3 -
// из hev_socks5_tunnel_get_session_stats.
package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"sync/atomic"
	"syscall"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

var (
	socksPort = flag.Int("socks", 31888, "socks port")
	logPath   = flag.String("log", "/tmp/hev-smoke.log", "hev log file")
	raceIters = flag.Int("race", 30, "relieve/stop race iterations")
)

const (
	reliefUDP = 1
	reliefTCP = 2
)

var passed, failed int

func check(name string, ok bool, detail string) {
	if ok {
		passed++
		fmt.Printf("PASS %s %s\n", name, detail)
	} else {
		failed++
		fmt.Printf("FAIL %s %s\n", name, detail)
	}
}

func cfg(extraMisc string) string {
	return fmt.Sprintf("tunnel:\n  mtu: 1500\nsocks5:\n  port: %d\n  address: 127.0.0.1\n  udp: 'udp'\n"+
		"misc:\n  task-stack-size: 24576\n  tcp-buffer-size: 4096\n  connect-timeout: 5000\n  read-write-timeout: 30000\n"+
		"  log-file: %s\n  log-level: warn\n  limit-nofile: 65535\n%s", *socksPort, *logPath, extraMisc)
}

var relieveLine = regexp.MustCompile(`relieve types (\d+) idle (\d+) max (\d+): udp (\d+) tcp (\d+) of (\d+)`)

type reliefResult struct{ udp, tcp, total int }

func logMatches() [][]string {
	f, err := os.Open(*logPath)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out [][]string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if m := relieveLine.FindStringSubmatch(sc.Text()); m != nil {
			out = append(out, m)
		}
	}
	return out
}

// relieveAndWait зовёт relieve и ждёт его строку в логе hev (задача relief пишет её асинхронно).
func relieveAndWait(types, idle, max int) (reliefResult, bool) {
	before := len(logMatches())
	if relieve(types, idle, max) != 0 {
		return reliefResult{}, false
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		ms := logMatches()
		if len(ms) > before {
			m := ms[len(ms)-1]
			if m[1] == strconv.Itoa(types) && m[2] == strconv.Itoa(idle) && m[3] == strconv.Itoa(max) {
				u, _ := strconv.Atoi(m[4])
				t, _ := strconv.Atoi(m[5])
				n, _ := strconv.Atoi(m[6])
				return reliefResult{u, t, n}, true
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	return reliefResult{}, false
}

func sessions() int {
	r, ok := relieveAndWait(0, 0, 0)
	if !ok {
		return -1
	}
	return r.total
}

func udpEcho(c *gonet.UDPConn, msg string) bool {
	return udpEchoWithin(c, msg, 2*time.Second)
}

// refusedWait - сколько ждать эха там, где ждём отказа: иначе каждая такая проверка стоит 2 с, и
// сессии пула DNS истекают по своему таймауту посреди шагов.
const refusedWait = 300 * time.Millisecond

func udpEchoWithin(c *gonet.UDPConn, msg string, wait time.Duration) bool {
	if _, err := c.Write([]byte(msg)); err != nil {
		return false
	}
	c.SetReadDeadline(time.Now().Add(wait))
	b := make([]byte, 256)
	n, err := c.Read(b)
	return err == nil && string(b[:n]) == msg
}

func tcpEcho(c net.Conn, msg string) bool {
	c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Write([]byte(msg)); err != nil {
		return false
	}
	b := make([]byte, len(msg))
	_, err := io.ReadFull(c, b)
	return err == nil && string(b) == msg
}

// rig - один запуск hev со своим socketpair и своим стеком gVisor.
type rig struct {
	s       *stack.Stack
	nsFD    int
	hevDone chan int
}

func newRig(config string) *rig {
	hevFD, nsFD := socketpair()
	r := &rig{nsFD: nsFD, hevDone: make(chan int, 1)}
	go func() {
		runtime.LockOSThread()
		r.hevDone <- startHev(config, hevFD)
	}()
	time.Sleep(300 * time.Millisecond)

	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	ep := channel.New(4096, 1500, "")
	if err := s.CreateNIC(1, ep); err != nil {
		panic(err)
	}
	s.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: tcpip.AddrFrom4([4]byte{10, 0, 0, 2}).WithPrefix()}, stack.AddressProperties{})
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})
	go func() {
		for {
			pkt := ep.ReadContext(context.Background())
			if pkt == nil {
				return
			}
			v := pkt.ToView()
			b := make([]byte, 4+v.Size())
			binary.BigEndian.PutUint32(b, syscall.AF_INET)
			copy(b[4:], v.AsSlice())
			v.Release()
			pkt.DecRef()
			syscall.Write(nsFD, b)
		}
	}()
	go func() {
		b := make([]byte, 65536)
		for {
			n, err := syscall.Read(nsFD, b)
			if err != nil {
				return
			}
			if n <= 4 {
				continue
			}
			pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(append([]byte(nil), b[4:n]...))})
			ep.InjectInbound(ipv4.ProtocolNumber, pkt)
			pkt.DecRef()
		}
	}()
	r.s = s
	return r
}

func remote(port uint16) *tcpip.FullAddress {
	return &tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte{1, 1, 1, 1}), Port: port}
}

func (r *rig) openUDP(n int, base uint16) []*gonet.UDPConn {
	var out []*gonet.UDPConn
	for i := 0; i < n; i++ {
		c, err := gonet.DialUDP(r.s, nil, remote(base+uint16(i)), ipv4.ProtocolNumber)
		if err != nil {
			panic(err)
		}
		out = append(out, c)
	}
	return out
}

func (r *rig) openUDPTo(addr [4]byte, port uint16) *gonet.UDPConn {
	c, err := gonet.DialUDP(r.s, nil, &tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(addr), Port: port}, ipv4.ProtocolNumber)
	if err != nil {
		panic(err)
	}
	return c
}

func (r *rig) dialTCP() net.Conn {
	c, err := gonet.DialContextTCP(context.Background(), r.s, *remote(7), ipv4.ProtocolNumber)
	if err != nil {
		return nil
	}
	return c
}

func (r *rig) quit(label string) {
	quitHev()
	select {
	case code := <-r.hevDone:
		check(label+": hev main returns after quit", code == 0, fmt.Sprintf("code=%d", code))
	case <-time.After(5 * time.Second):
		check(label+": hev main returns after quit", false, "hang > 5 s")
	}
	r.s.Close()
	syscall.Close(r.nsFD)
}

func allEcho(cs []*gonet.UDPConn, tag string) bool {
	ok := true
	for i, c := range cs {
		ok = udpEcho(c, fmt.Sprintf("%s-%d", tag, i)) && ok
	}
	return ok
}

// burstEcho шлёт по датаграмме во все потоки сразу и только потом ждёт ответы: так все
// новые сессии просятся в hev, пока живые ещё не успели замолчать.
func burstEcho(cs []*gonet.UDPConn, tag string) int {
	for i, c := range cs {
		c.Write([]byte(fmt.Sprintf("%s-%d", tag, i)))
	}
	n := 0
	b := make([]byte, 256)
	for i, c := range cs {
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		m, err := c.Read(b)
		if err == nil && string(b[:m]) == fmt.Sprintf("%s-%d", tag, i) {
			n++
		}
	}
	return n
}

func mustStats() sessionStats {
	s, ok := stats()
	if !ok {
		panic("get_session_stats failed")
	}
	return s
}

func partR8() {
	check("relieve before any start returns -1", relieve(reliefUDP, 0, 0) == -1, "")
	r := newRig(cfg(""))

	long := r.openUDP(5, 21100)
	check("udp echo", allEcho(long, "long"), "")
	time.Sleep(3500 * time.Millisecond)
	n := sessions()
	check("udp sessions alive after 3.5 s idle at 30 s timeout", n == 5, fmt.Sprintf("sessions=%d", n))

	// 2. relieve: только простаивающие, max_count, все UDP, TCP не трогает, туннель живёт.
	var tcps []net.Conn
	for i := 0; i < 3; i++ {
		c := r.dialTCP()
		if c == nil {
			panic("tcp dial")
		}
		tcps = append(tcps, c)
	}
	tcpOK := true
	for i, c := range tcps {
		tcpOK = tcpEcho(c, fmt.Sprintf("tcp-%d", i)) && tcpOK
	}
	check("tcp echo before relieve", tcpOK, "")
	fresh := r.openUDP(5, 21200)
	check("fresh udp echo", allEcho(fresh, "fresh"), "")
	rr, ok := relieveAndWait(reliefUDP, 2000, 0)
	check("relieve(udp, idle 2000) closes only the 5 idle udp", ok && rr.udp == 5 && rr.tcp == 0 && rr.total == 13, fmt.Sprintf("%+v", rr))
	time.Sleep(300 * time.Millisecond)
	n = sessions()
	check("8 sessions left after idle relieve", n == 8, fmt.Sprintf("sessions=%d", n))
	rr, ok = relieveAndWait(reliefUDP, 0, 2)
	check("relieve(udp, max 2) closes 2", ok && rr.udp == 2 && rr.tcp == 0, fmt.Sprintf("%+v", rr))
	time.Sleep(300 * time.Millisecond)
	rr, ok = relieveAndWait(reliefUDP, 0, 0)
	check("relieve(udp) closes the remaining 3 udp", ok && rr.udp == 3 && rr.tcp == 0 && rr.total == 6, fmt.Sprintf("%+v", rr))
	time.Sleep(300 * time.Millisecond)
	n = sessions()
	check("only 3 tcp left", n == 3, fmt.Sprintf("sessions=%d", n))
	tcpOK = true
	for i, c := range tcps {
		tcpOK = tcpEcho(c, fmt.Sprintf("again-%d", i)) && tcpOK
	}
	check("tcp survives udp relieve", tcpOK, "")
	check("relieved udp flow gets a new session and echo", udpEcho(fresh[0], "after-relieve"), "")
	rr, ok = relieveAndWait(reliefTCP, 0, 1)
	check("relieve(tcp, max 1) closes the least recently active tcp", ok && rr.tcp == 1 && rr.udp == 0, fmt.Sprintf("%+v", rr))
	time.Sleep(300 * time.Millisecond)
	check("closed tcp conn fails", !tcpEcho(tcps[0], "dead"), "")
	check("other tcp conns still echo", tcpEcho(tcps[1], "alive-1") && tcpEcho(tcps[2], "alive-2"), "")

	r.quit("r8")
	check("relieve after stop returns -1", relieve(reliefUDP, 0, 0) == -1, "")

	// 3. Гонка relieve с остановкой: relieve в цикле из другого потока, пока hev стартует и останавливается.
	var okCalls, failCalls atomic.Int64
	hangs, lateOK := 0, 0
	for i := 0; i < *raceIters; i++ {
		fa, fb := socketpair()
		done := make(chan int, 1)
		go func() {
			runtime.LockOSThread()
			done <- startHev(cfg(""), fa)
		}()
		var stop atomic.Bool
		hammerDone := make(chan struct{})
		go func() {
			runtime.LockOSThread()
			for !stop.Load() {
				if relieve(reliefUDP, 0, 0) == 0 {
					okCalls.Add(1)
				} else {
					failCalls.Add(1)
				}
				time.Sleep(200 * time.Microsecond)
			}
			close(hammerDone)
		}()
		time.Sleep(time.Duration(i%5) * 10 * time.Millisecond)
		quitHev()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			hangs++
		}
		time.Sleep(20 * time.Millisecond)
		stop.Store(true)
		<-hammerDone
		if relieve(reliefUDP, 0, 0) != -1 {
			lateOK++
		}
		syscall.Close(fb)
	}
	check("race: no hang on stop", hangs == 0, fmt.Sprintf("iters=%d hangs=%d", *raceIters, hangs))
	check("race: relieve after stop always -1", lateOK == 0, fmt.Sprintf("late_ok=%d", lateOK))
	check("race: relieve succeeded while running", okCalls.Load() > 0, fmt.Sprintf("ok=%d fail=%d", okCalls.Load(), failCalls.Load()))
}

// stillLive: эхо прошло на старой сессии hev, новая UDP не создавалась.
func stillLive(c *gonet.UDPConn, msg string) bool {
	before := mustStats().udpCreated
	return udpEcho(c, msg) && mustStats().udpCreated == before
}

// reborn: старой сессии потока уже нет, эхо пришло через новую.
func reborn(c *gonet.UDPConn, msg string) bool {
	before := mustStats().udpCreated
	return udpEcho(c, msg) && mustStats().udpCreated == before+1
}

func noReply(cs []*gonet.UDPConn, tag string) {
	for i, c := range cs {
		c.Write([]byte(fmt.Sprintf("NOREPLY-%s-%d", tag, i)))
	}
}

// G1, G2. Одна таблица UDP и TCP на max-session-count 4: новый поток у потолка вытесняет давнее
// всех активный и никогда не получает отказ.
func partTable() {
	check("stats refuse a too small size", statsWithSize(8) == -1, "")
	r := newRig(cfg("  max-session-count: 4\n  max-buffer-size: 1048576\n"))
	s := mustStats()
	check("G1 stats show max-session-count and max-buffer-size from config, no caps per type",
		s.maxSessionCount == 4 && s.udpCap == 0 && s.tcpCap == 0 && s.bufferLimit == 1048576,
		fmt.Sprintf("max=%d udp_cap=%d tcp_cap=%d buffer_limit=%d", s.maxSessionCount, s.udpCap, s.tcpCap, s.bufferLimit))

	first := r.openUDP(4, 22000)
	check("G1 4 udp flows echo", allEcho(first, "g1"), "")
	extra := r.openUDP(2, 22100)
	ok := udpEcho(extra[0], "g1x0") && udpEcho(extra[1], "g1x1")
	s = mustStats()
	check("G1 new flows at the cap get in, the table stays at exactly 4",
		ok && s.udpLive == 4 && s.udpEvicted == 2 && s.udpRefused == 0,
		fmt.Sprintf("echo=%v live=%d evicted=%d refused=%d", ok, s.udpLive, s.udpEvicted, s.udpRefused))
	check("G1 the more recently active flows kept their sessions",
		stillLive(first[2], "g1k2") && stillLive(first[3], "g1k3") && stillLive(extra[0], "g1k4") && stillLive(extra[1], "g1k5"), "")
	b := mustStats()
	ok = reborn(first[0], "g1r")
	s = mustStats()
	check("G1 the least recently active flow was the one evicted",
		ok && s.udpEvicted == b.udpEvicted+1 && s.udpLive == 4,
		fmt.Sprintf("echo=%v evicted=%d->%d live=%d", ok, b.udpEvicted, s.udpEvicted, s.udpLive))

	// G2. TCP в той же таблице: соединение вытесняет UDP, а давнее всех активное TCP вытесняется само.
	b = mustStats()
	t1 := r.dialTCP()
	ok = t1 != nil && tcpEcho(t1, "t1")
	s = mustStats()
	check("G2 tcp at the cap takes the place of the least recently active udp",
		ok && s.tcpLive == 1 && s.udpLive == 3 && s.udpEvicted == b.udpEvicted+1,
		fmt.Sprintf("echo=%v tcp_live=%d udp_live=%d evicted=%d->%d", ok, s.tcpLive, s.udpLive, b.udpEvicted, s.udpEvicted))
	check("G2 the remaining udp flows echo", udpEcho(extra[0], "g2a") && udpEcho(extra[1], "g2b") && udpEcho(first[0], "g2c"), "")
	n := r.openUDP(1, 22200)
	ok = udpEcho(n[0], "g2n")
	t1ok := tcpEcho(t1, "t1b")
	s = mustStats()
	check("G2 a least recently active tcp connection is evicted and reset",
		ok && !t1ok && s.tcpEvicted == 1 && s.tcpLive == 0 && s.udpLive == 4,
		fmt.Sprintf("echo=%v tcp=%v tcp_evicted=%d tcp_live=%d udp_live=%d", ok, t1ok, s.tcpEvicted, s.tcpLive, s.udpLive))

	b = mustStats()
	got := burstEcho(r.openUDP(4, 22300), "g1b")
	s = mustStats()
	check("G1 a burst of 4 new flows on a full table replaces the 4 old ones, none refused",
		got == 4 && s.udpLive == 4 && s.udpEvicted == b.udpEvicted+4 && s.udpRefused == 0,
		fmt.Sprintf("echo=%d/4 live=%d evicted=%d->%d refused=%d", got, s.udpLive, b.udpEvicted, s.udpEvicted, s.udpRefused))
	r.quit("table")
}

// Защита из evict-protect-idle 4000: поток с ответом, который говорил хотя бы через 2 с после
// создания, не вытесняется, пока молчит меньше 4 с. Поток с ответом моложе 2 с тоже держится.
const protectConf = "  max-session-count: 4\n  evict-protect-idle: 4000\n"

// G3. Ответивший и ещё говорящий поток защищён, вытесняется молчащий; защита кончается через
// evict-protect-idle тишины.
func partProtect() {
	r := newRig(cfg(protectConf))
	s := mustStats()
	check("G6 restart re-reads the config and resets counters",
		s.maxSessionCount == 4 && s.bufferLimit == 0 && s.udpCreated == 0 && s.udpEvicted == 0,
		fmt.Sprintf("max=%d buffer_limit=%d created=%d evicted=%d", s.maxSessionCount, s.bufferLimit, s.udpCreated, s.udpEvicted))

	a := r.openUDP(1, 23000)[0]
	check("G3 talker answers", udpEcho(a, "g3a"), "")
	time.Sleep(2500 * time.Millisecond)
	check("G3 talker still talks 2.5 s after it started", udpEcho(a, "g3a2"), "")
	others := r.openUDP(3, 23100)
	check("G3 3 one-shot flows echo after it", allEcho(others, "g3o"), "")
	// Одноразовые потоки старше 2 с, говорящий молчит 2.5 с из 4 и при этом давнее всех активен.
	time.Sleep(2500 * time.Millisecond)
	b := mustStats()
	e := r.openUDP(1, 23200)[0]
	ok := udpEcho(e, "g3e")
	s = mustStats()
	check("G3 a new flow at the cap evicts a silent one-shot flow, not the protected talker",
		ok && s.udpEvicted == b.udpEvicted+1 && s.udpLive == 4 && s.protectedLive == 1,
		fmt.Sprintf("echo=%v evicted=%d->%d live=%d protected=%d", ok, b.udpEvicted, s.udpEvicted, s.udpLive, s.protectedLive))
	check("G3 the evicted one was the least recently active one-shot flow", reborn(others[0], "g3r"), "")

	// Говорящий молчит 5 с из 4: защиты больше нет, он давнее всех активен и уходит первым.
	time.Sleep(2500 * time.Millisecond)
	b = mustStats()
	f := r.openUDP(1, 23300)[0]
	ok = udpEcho(f, "g3f")
	s = mustStats()
	check("G3 after evict-protect-idle of silence the talker is no longer protected",
		ok && s.udpEvicted == b.udpEvicted+1 && s.protectedLive == 0 && reborn(a, "g3a3"),
		fmt.Sprintf("echo=%v evicted=%d->%d protected=%d", ok, b.udpEvicted, s.udpEvicted, s.protectedLive))
	r.quit("protect")
}

// G4. Защищённые держат не больше половины таблицы: при всех защищённых новый поток всё равно входит,
// а защищённых остаётся 2 из 4.
func partProtectHalf() {
	r := newRig(cfg(protectConf))
	talkers := r.openUDP(4, 23400)
	check("G4 4 flows echo", allEcho(talkers, "g4"), "")
	time.Sleep(2500 * time.Millisecond)
	check("G4 4 flows still talk 2.5 s after they started", allEcho(talkers, "g4b"), "")
	var prot []int
	ok := true
	for i, c := range r.openUDP(4, 23500) {
		ok = udpEcho(c, fmt.Sprintf("g4n-%d", i)) && ok
		prot = append(prot, mustStats().protectedLive)
	}
	s := mustStats()
	check("G4 with all flows protected new flows still get in",
		ok && s.udpLive == 4 && s.udpEvicted == 4 && s.udpRefused == 0,
		fmt.Sprintf("echo=%v live=%d evicted=%d refused=%d", ok, s.udpLive, s.udpEvicted, s.udpRefused))
	check("G4 protected flows are evicted down to half of the table and no further",
		len(prot) == 4 && prot[0] == 4 && prot[1] == 3 && prot[2] == 2 && prot[3] == 2, fmt.Sprintf("protected=%v", prot))
	check("G4 the two most recently active protected flows kept their sessions",
		stillLive(talkers[2], "g4k2") && stillLive(talkers[3], "g4k3"), "")
	r.quit("protect-half")
}

// G7. Поток с одним обменом молод 2 с и держится, потом не защищён. Остальные места заняты потоками
// без ответа: они не молоды и не защищены, вытесняется один из них, если одноразовый держится.
func partYoung() {
	r := newRig(cfg(protectConf))
	a := r.openUDP(1, 23600)[0]
	check("G7 one-shot flow answers", udpEcho(a, "g7a"), "")
	noReply(r.openUDP(3, 23700), "g7")
	time.Sleep(200 * time.Millisecond)
	b := mustStats()
	ok := udpEcho(r.openUDP(1, 23800)[0], "g7e")
	s := mustStats()
	check("G7 a flow answered under 2 s ago is kept, an unanswered one is evicted",
		ok && b.udpLive == 4 && s.udpEvicted == b.udpEvicted+1 && stillLive(a, "g7a2"),
		fmt.Sprintf("echo=%v live=%d evicted=%d->%d", ok, b.udpLive, b.udpEvicted, s.udpEvicted))

	_, relieved := relieveAndWait(reliefUDP, 0, 0)
	time.Sleep(300 * time.Millisecond)
	check("G7 relieve clears the table", relieved && mustStats().udpLive == 0, "")
	a = r.openUDP(1, 23900)[0]
	check("G7 second one-shot flow answers", udpEcho(a, "g7b"), "")
	noReply(r.openUDP(3, 24000), "g7b")
	time.Sleep(2500 * time.Millisecond)
	b = mustStats()
	ok = udpEcho(r.openUDP(1, 24100)[0], "g7f")
	s = mustStats()
	check("G7 2.5 s later the one-shot flow is neither young nor protected and goes first",
		ok && b.udpLive == 4 && s.udpEvicted == b.udpEvicted+1 && reborn(a, "g7b2"),
		fmt.Sprintf("echo=%v live=%d evicted=%d->%d", ok, b.udpLive, b.udpEvicted, s.udpEvicted))
	r.quit("young")
}

// G5. Колбэк памяти: HOLD только UDP, CLOSED UDP и TCP, пороги 12 / 8 МБ, гистерезис 2 МБ.
func partProbe() {
	r := newRig(cfg("  max-session-count: 16\n"))
	udps := r.openUDP(3, 24200)
	t1, t2 := r.dialTCP(), r.dialTCP()
	check("G5 3 udp and 2 tcp echo", allEcho(udps, "g5") && t1 != nil && t2 != nil && tcpEcho(t1, "t1") && tcpEcho(t2, "t2"), "")
	check("G5 probe types hold=udp close=all", setProbeTypes(sessUDP, sessUDP|sessTCP) == 0, "")
	setFakeAvailKB(11 * 1024)
	check("G5 probe on", probeOn(0, 12*1024, 8*1024, 2*1024, 1000, 0) == 0, "")
	time.Sleep(100 * time.Millisecond)

	b := mustStats()
	hold := r.openUDP(2, 24300)
	ok := udpEcho(hold[0], "g5h0") && udpEcho(hold[1], "g5h1")
	s := mustStats()
	check("G5 hold: new udp flows get in in place of live udp, udp does not grow",
		ok && s.admUDP == admitHold && s.admTCP == admitOpen && s.udpLive == 3 && s.udpEvicted == b.udpEvicted+2 &&
			s.udpRefused == b.udpRefused && s.udpRefusedAdm == b.udpRefusedAdm,
		fmt.Sprintf("echo=%v adm=%d/%d udp_live=%d evicted=%d->%d refused=%d->%d refused_adm=%d->%d", ok, s.admUDP, s.admTCP,
			s.udpLive, b.udpEvicted, s.udpEvicted, b.udpRefused, s.udpRefused, b.udpRefusedAdm, s.udpRefusedAdm))
	check("G5 hold for udp does not evict tcp", s.tcpLive == 2 && s.tcpEvicted == 0 && tcpEcho(t1, "t1h") && tcpEcho(t2, "t2h"),
		fmt.Sprintf("tcp_live=%d tcp_evicted=%d", s.tcpLive, s.tcpEvicted))
	check("G5 hold evicted the least recently active udp flows", reborn(udps[0], "g5r"), "")
	t3 := r.dialTCP()
	ok = t3 != nil && tcpEcho(t3, "t3")
	s = mustStats()
	check("G5 tcp still grows while udp holds", ok && s.tcpLive == 3 && s.udpLive == 3,
		fmt.Sprintf("echo=%v tcp_live=%d udp_live=%d", ok, s.tcpLive, s.udpLive))

	_, relieved := relieveAndWait(reliefUDP, 0, 0)
	time.Sleep(300 * time.Millisecond)
	s = mustStats()
	check("G5 relieve closes all udp", relieved && s.udpLive == 0, fmt.Sprintf("live=%d", s.udpLive))
	b = s
	ok = udpEcho(r.openUDP(1, 24400)[0], "g5e")
	s = mustStats()
	check("G5 hold with no live udp admits a new one", ok && s.admUDP == admitHold && s.udpLive == 1 && s.udpEvicted == b.udpEvicted,
		fmt.Sprintf("echo=%v adm=%d live=%d evicted=%d->%d", ok, s.admUDP, s.udpLive, b.udpEvicted, s.udpEvicted))

	setFakeAvailKB(5 * 1024)
	time.Sleep(100 * time.Millisecond)
	b = mustStats()
	c1 := r.openUDP(1, 24500)
	c1ok := udpEchoWithin(c1[0], "g5c", refusedWait)
	t4 := r.dialTCP()
	t4ok := t4 != nil && tcpEcho(t4, "t4")
	s = mustStats()
	check("G5 below close: new udp and tcp refused and counted",
		!c1ok && !t4ok && s.admUDP == admitClosed && s.admTCP == admitClosed &&
			s.udpRefused == b.udpRefused+1 && s.udpRefusedAdm == b.udpRefusedAdm+1 &&
			s.tcpRefused == b.tcpRefused+1 && s.tcpRefusedAdm == b.tcpRefusedAdm+1,
		fmt.Sprintf("udp=%v tcp=%v adm=%d/%d udp_refused=%d->%d tcp_refused=%d->%d", c1ok, t4ok, s.admUDP, s.admTCP,
			b.udpRefused, s.udpRefused, b.tcpRefused, s.tcpRefused))
	check("G5 closed: live sessions keep working", tcpEcho(t1, "t1c") && tcpEcho(t3, "t3c"), "")
	check("G5 probe result is reported", s.lastProbeKB == 5*1024 && probeCalls() > 0,
		fmt.Sprintf("probe_kb=%d calls=%d", s.lastProbeKB, probeCalls()))

	setFakeAvailKB(11 * 1024)
	time.Sleep(100 * time.Millisecond)
	t5 := r.dialTCP()
	t5ok := t5 != nil && tcpEcho(t5, "t5")
	s = mustStats()
	check("G5 between thresholds after closed: udp hold, tcp open", t5ok && s.admUDP == admitHold && s.admTCP == admitOpen,
		fmt.Sprintf("tcp=%v adm=%d/%d", t5ok, s.admUDP, s.admTCP))

	setFakeAvailKB(13 * 1024)
	time.Sleep(100 * time.Millisecond)
	b = mustStats()
	ok = udpEcho(r.openUDP(1, 24600)[0], "g5h2")
	s = mustStats()
	check("G5 hysteresis keeps hold just above the hold threshold",
		ok && s.admUDP == admitHold && s.udpLive == b.udpLive && s.udpEvicted == b.udpEvicted+1,
		fmt.Sprintf("echo=%v adm_udp=%d live=%d->%d evicted=%d->%d", ok, s.admUDP, b.udpLive, s.udpLive, b.udpEvicted, s.udpEvicted))

	setFakeAvailKB(20 * 1024)
	time.Sleep(100 * time.Millisecond)
	b = mustStats()
	ok = udpEcho(r.openUDP(1, 24700)[0], "g5o")
	s = mustStats()
	check("G5 plenty of memory: open again, udp grows", ok && s.admUDP == admitOpen && s.admTCP == admitOpen && s.udpLive == b.udpLive+1,
		fmt.Sprintf("echo=%v adm=%d/%d live=%d->%d", ok, s.admUDP, s.admTCP, b.udpLive, s.udpLive))
	check("G5 probe off", probeOff() == 0 && setProbeTypes(sessUDP|sessTCP, sessUDP|sessTCP) == 0, "")
	setFakeAvailKB(1024)
	time.Sleep(100 * time.Millisecond)
	check("G5 probe off ignores the probe", udpEcho(r.openUDP(1, 24800)[0], "g5off"), "")
	r.quit("probe")
}

// G8. HOLD с защитой: защищённые UDP держат не больше половины живых UDP, новые потоки входят
// без отказа, TCP не трогается.
func partProbeProtect() {
	r := newRig(cfg("  max-session-count: 16\n  evict-protect-idle: 4000\n"))
	talkers := r.openUDP(4, 24900)
	t1 := r.dialTCP()
	check("G8 4 udp and 1 tcp echo", allEcho(talkers, "g8") && t1 != nil && tcpEcho(t1, "g8t"), "")
	time.Sleep(2500 * time.Millisecond)
	check("G8 4 udp still talk 2.5 s after they started", allEcho(talkers, "g8b"), "")
	check("G8 probe types hold=udp close=all", setProbeTypes(sessUDP, sessUDP|sessTCP) == 0, "")
	setFakeAvailKB(11 * 1024)
	check("G8 probe on, hold", probeOn(0, 12*1024, 8*1024, 0, 1000, 0) == 0, "")
	time.Sleep(100 * time.Millisecond)

	b := mustStats()
	ok := true
	for i, c := range r.openUDP(4, 25000) {
		ok = udpEcho(c, fmt.Sprintf("g8n-%d", i)) && ok
	}
	s := mustStats()
	check("G8 hold with protected flows: new udp get in, udp does not grow, nothing refused",
		ok && s.admUDP == admitHold && s.udpLive == 4 && s.udpEvicted == b.udpEvicted+4 && s.udpRefused == b.udpRefused,
		fmt.Sprintf("echo=%v adm=%d live=%d evicted=%d->%d refused=%d->%d", ok, s.admUDP, s.udpLive,
			b.udpEvicted, s.udpEvicted, b.udpRefused, s.udpRefused))
	check("G8 protected udp are evicted down to half of the live udp and no further",
		stillLive(talkers[2], "g8k2") && stillLive(talkers[3], "g8k3"), "")
	check("G8 hold does not evict tcp", s.tcpLive == 1 && s.tcpEvicted == 0 && tcpEcho(t1, "g8t2"),
		fmt.Sprintf("tcp_live=%d tcp_evicted=%d", s.tcpLive, s.tcpEvicted))
	check("G8 probe off", probeOff() == 0 && setProbeTypes(sessUDP|sessTCP, sessUDP|sessTCP) == 0, "")
	r.quit("probe-protect")
}

// Проверки правок по ревью патчей: K5 пороги колбэка, H5 и K6 свежесть оценки памяти в статистике.
func partReview() {
	check("K5 close above hold is rejected", probeOn(0, 8*1024, 12*1024, 0, 0, 0) == -1, "")
	check("K5 negative hysteresis is rejected", probeOn(0, 12*1024, 8*1024, -1, 0, 0) == -1, "")

	r := newRig(cfg(""))
	setFakeAvailKB(10 * 1024)
	check("H5 probe on", probeOn(0, 12*1024, 8*1024, 0, 0, 0) == 0, "")
	time.Sleep(100 * time.Millisecond)
	ok := udpEcho(r.openUDP(1, 24900)[0], "h5")
	s := mustStats()
	check("H5 hold admits the first udp flow", ok && s.admUDP == admitHold, fmt.Sprintf("echo=%v adm=%d", ok, s.admUDP))
	setFakeAvailKB(20 * 1024)
	time.Sleep(600 * time.Millisecond)
	s = mustStats()
	check("H5 stats follow memory without new sessions", s.admUDP == admitOpen && s.lastProbeKB == 20*1024,
		fmt.Sprintf("adm=%d probe_kb=%d", s.admUDP, s.lastProbeKB))
	check("H5 time in hold is counted and stops after hold", s.probeHoldMs >= 100 && s.probeClosedMs == 0,
		fmt.Sprintf("hold_ms=%d closed_ms=%d", s.probeHoldMs, s.probeClosedMs))
	time.Sleep(300 * time.Millisecond)
	later := mustStats()
	check("H5 time in hold does not grow while open", later.probeHoldMs == s.probeHoldMs,
		fmt.Sprintf("hold_ms=%d->%d", s.probeHoldMs, later.probeHoldMs))
	r.quit("stale-probe")

	r = newRig(cfg(""))
	s = mustStats()
	check("K6 restart forgets the previous probe result and state time", s.lastProbeKB == -1 && s.probeHoldMs == 0,
		fmt.Sprintf("probe_kb=%d hold_ms=%d", s.lastProbeKB, s.probeHoldMs))
	check("K6 probe off", probeOff() == 0, "")
	r.quit("probe-reset")
	_, ok = stats()
	check("W4 stats are unavailable once the tunnel has stopped", !ok, "")
}

// D. Пул DNS (0009): UDP на 53 к адресам из списка идёт в свой пул мимо таблицы max-session-count
// и колбэка памяти.
func partDNS() {
	// Таблица на 4. Таймаут пула 4 с: шаги D1-D3 укладываются в 2 с, D4 ждёт его истечения.
	conf := "  max-session-count: 4\n" +
		"  dns-priority-sessions: 2\n  dns-priority-timeout: 4000\n  dns-priority-addresses: '9.9.9.9,8.8.8.8'\n"
	r := newRig(cfg(conf))
	ret, size, untouched := statsCallerWithSize(statsGuardSize())
	check("D0 stats accept the size of a caller without dns fields and write nothing past it",
		ret == 0 && size == statsGuardSize() && untouched, fmt.Sprintf("ret=%d size=%d/%d untouched=%v", ret, size, statsGuardSize(), untouched))
	check("D0 stats refuse a size below that", statsWithSize(statsGuardSize()-1) == -1, "")

	s := mustStats()
	check("D1 pool comes from config", s.dnsCap == 2 && s.dnsLive == 0, fmt.Sprintf("dns_cap=%d dns_live=%d", s.dnsCap, s.dnsLive))
	fill := r.openUDP(4, 25000)
	check("D1 4 udp flows fill the table", allEcho(fill, "d1"), "")
	b := mustStats()
	eok := udpEcho(r.openUDP(1, 25100)[0], "d1x")
	s = mustStats()
	check("D1 control: a new udp flow on a full table evicts one", eok && s.udpLive == 4 && s.udpEvicted == b.udpEvicted+1,
		fmt.Sprintf("echo=%v live=%d evicted=%d->%d", eok, s.udpLive, b.udpEvicted, s.udpEvicted))
	b = s
	q1 := r.openUDPTo([4]byte{9, 9, 9, 9}, 53)
	q1ok := udpEcho(q1, "d1q")
	s = mustStats()
	check("D1 dns to a listed resolver passes the full table, does not count in it and evicts nothing",
		q1ok && s.dnsLive == 1 && s.dnsCreated == 1 && s.udpLive == 4 && s.udpEvicted == b.udpEvicted,
		fmt.Sprintf("echo=%v dns_live=%d dns_created=%d udp_live=%d evicted=%d->%d", q1ok, s.dnsLive, s.dnsCreated, s.udpLive, b.udpEvicted, s.udpEvicted))
	b = s
	u1 := r.openUDPTo([4]byte{1, 1, 1, 1}, 53)
	u1ok := udpEcho(u1, "d1u")
	s = mustStats()
	check("D1 port 53 of an unlisted address is ordinary udp and takes a place in the table",
		u1ok && s.udpEvicted == b.udpEvicted+1 && s.udpLive == 4 && s.dnsCreated == 1,
		fmt.Sprintf("echo=%v evicted=%d->%d udp_live=%d dns_created=%d", u1ok, b.udpEvicted, s.udpEvicted, s.udpLive, s.dnsCreated))

	// D2. Колбэк памяти, пороги 12 / 8 МБ: 11 МБ - HOLD для UDP, 5 МБ - CLOSED.
	setFakeAvailKB(11 * 1024)
	check("D2 probe on, hold=udp close=all, 11 MB left",
		setProbeTypes(sessUDP, sessUDP|sessTCP) == 0 && probeOn(0, 12*1024, 8*1024, 2*1024, 1000, 0) == 0, "")
	time.Sleep(100 * time.Millisecond)
	b = mustStats()
	h1ok := udpEcho(r.openUDP(1, 25200)[0], "d2h")
	s = mustStats()
	check("D2 control: hold lets a new udp flow in only in place of another",
		h1ok && s.admUDP == admitHold && s.udpLive == 4 && s.udpEvicted == b.udpEvicted+1 && s.udpRefused == b.udpRefused,
		fmt.Sprintf("echo=%v adm_udp=%d live=%d evicted=%d->%d refused=%d->%d", h1ok, s.admUDP, s.udpLive, b.udpEvicted, s.udpEvicted, b.udpRefused, s.udpRefused))
	b = s
	q2 := r.openUDPTo([4]byte{8, 8, 8, 8}, 53)
	q2ok := udpEcho(q2, "d2q")
	s = mustStats()
	check("D2 dns to a listed resolver passes in hold and evicts no udp",
		q2ok && s.dnsLive == 2 && s.dnsCreated == 2 && s.udpEvicted == b.udpEvicted,
		fmt.Sprintf("echo=%v dns_live=%d dns_created=%d evicted=%d->%d", q2ok, s.dnsLive, s.dnsCreated, b.udpEvicted, s.udpEvicted))
	setFakeAvailKB(5 * 1024)
	time.Sleep(100 * time.Millisecond)
	b = mustStats()
	c1ok := udpEchoWithin(r.openUDP(1, 25300)[0], "d2c", refusedWait)
	s = mustStats()
	check("D2 control: closed refuses a new udp flow", !c1ok && s.admUDP == admitClosed && s.udpRefused == b.udpRefused+1,
		fmt.Sprintf("echo=%v adm_udp=%d refused=%d->%d", c1ok, s.admUDP, b.udpRefused, s.udpRefused))
	q3 := r.openUDPTo([4]byte{9, 9, 9, 9}, 53)
	q3ok := udpEcho(q3, "d2q3")
	s = mustStats()
	check("D2 in closed a full pool gives up an answered session for a new query",
		q3ok && s.dnsLive == 2 && s.dnsCreated == 3 && s.dnsEvicted == 1,
		fmt.Sprintf("echo=%v dns_live=%d created=%d evicted=%d", q3ok, s.dnsLive, s.dnsCreated, s.dnsEvicted))

	// D3. Три запроса разом после секунды тишины: первые два вытесняют отвеченные, третий застаёт
	// пул из двух молодых без ответа и идёт обычным путём, а там CLOSED.
	time.Sleep(1200 * time.Millisecond)
	before := s
	burst := []*gonet.UDPConn{
		r.openUDPTo([4]byte{9, 9, 9, 9}, 53), r.openUDPTo([4]byte{8, 8, 8, 8}, 53), r.openUDPTo([4]byte{9, 9, 9, 9}, 53),
	}
	got := burstEcho(burst, "d3")
	s = mustStats()
	check("D3 a pool full of young unanswered queries does not take the next one",
		got == 2 && s.dnsRefused == before.dnsRefused+1 && s.dnsEvicted == before.dnsEvicted+2 && s.udpRefused == before.udpRefused+1,
		fmt.Sprintf("echo=%d/3 refused=%d->%d evicted=%d->%d udp_refused=%d->%d", got, before.dnsRefused, s.dnsRefused,
			before.dnsEvicted, s.dnsEvicted, before.udpRefused, s.udpRefused))

	// D4. У сессий пула свой таймаут 4 с, обычные UDP живут по read-write-timeout 30 с.
	time.Sleep(5 * time.Second)
	s = mustStats()
	check("D4 pool sessions time out after dns-priority-timeout, ordinary udp stays", s.dnsLive == 0 && s.udpLive == 4,
		fmt.Sprintf("dns_live=%d udp_live=%d", s.dnsLive, s.udpLive))
	check("D4 probe off", probeOff() == 0 && setProbeTypes(sessUDP|sessTCP, sessUDP|sessTCP) == 0, "")
	r.quit("dns")
}

// D6. Запрос, не влезший в полный пул молодых без ответа (0011), идёт обычным путём UDP: при открытом
// приёме стартует обычной сессией, в HOLD встаёт на место живой UDP, в CLOSED получает отказ.
func partDNSOverflow() {
	// Таблица на 8 с запасом, пул 2 на 9.9.9.9: четыре запроса разом - два в пул, два мимо него.
	conf := "  max-session-count: 8\n" +
		"  dns-priority-sessions: 2\n  dns-priority-timeout: 4000\n  dns-priority-addresses: '9.9.9.9'\n"
	r := newRig(cfg(conf))
	ret, size, untouched := statsCallerWithSize(statsPoolSize())
	check("D6 stats accept the size of a caller without dns_overflow and write nothing past it",
		ret == 0 && size == statsPoolSize() && untouched, fmt.Sprintf("ret=%d size=%d untouched=%v", ret, size, untouched))
	ret, size, untouched = statsCallerWithSize(statsBudgetSize())
	check("S1 stats accept the size of a caller without the memory budget fields and write nothing past it",
		ret == 0 && size == statsBudgetSize() && untouched, fmt.Sprintf("ret=%d size=%d untouched=%v", ret, size, untouched))

	burst := func(tag string) (int, sessionStats, sessionStats) {
		// Пауза разводит пачки: ответы и отказы предыдущей уже дошли.
		time.Sleep(1200 * time.Millisecond)
		before := mustStats()
		var cs []*gonet.UDPConn
		for i := 0; i < 4; i++ {
			cs = append(cs, r.openUDPTo([4]byte{9, 9, 9, 9}, 53))
		}
		got := burstEcho(cs, tag)
		return got, before, mustStats()
	}
	got, b, s := burst("d6o")
	check("D6 open: queries over a full pool start as ordinary udp sessions",
		got == 4 && s.dnsRefused == b.dnsRefused+2 && s.dnsOverflow == b.dnsOverflow+2 && s.dnsLive == 2 && s.udpLive == 2,
		fmt.Sprintf("echo=%d/4 dns_refused=%d->%d dns_overflow=%d->%d dns_live=%d udp_live=%d",
			got, b.dnsRefused, s.dnsRefused, b.dnsOverflow, s.dnsOverflow, s.dnsLive, s.udpLive))

	setFakeAvailKB(11 * 1024)
	check("D6 probe on, hold=udp close=all, 11 MB left",
		setProbeTypes(sessUDP, sessUDP|sessTCP) == 0 && probeOn(0, 12*1024, 8*1024, 2*1024, 1000, 0) == 0, "")
	time.Sleep(100 * time.Millisecond)
	got, b, s = burst("d6h")
	check("D6 hold: queries over a full pool take the place of live udp sessions",
		got == 4 && s.admUDP == admitHold && s.dnsRefused == b.dnsRefused+2 && s.dnsOverflow == b.dnsOverflow+2 &&
			s.udpLive == b.udpLive && s.udpEvicted == b.udpEvicted+2 && s.udpRefusedAdm == b.udpRefusedAdm,
		fmt.Sprintf("echo=%d/4 adm_udp=%d dns_refused=%d->%d dns_overflow=%d->%d udp_live=%d->%d evicted=%d->%d refused_adm=%d->%d",
			got, s.admUDP, b.dnsRefused, s.dnsRefused, b.dnsOverflow, s.dnsOverflow, b.udpLive, s.udpLive,
			b.udpEvicted, s.udpEvicted, b.udpRefusedAdm, s.udpRefusedAdm))

	setFakeAvailKB(5 * 1024)
	time.Sleep(100 * time.Millisecond)
	got, b, s = burst("d6c")
	check("D6 closed: queries over a full pool are refused like new udp",
		got == 2 && s.admUDP == admitClosed && s.dnsRefused == b.dnsRefused+2 && s.dnsOverflow == b.dnsOverflow &&
			s.udpRefusedAdm == b.udpRefusedAdm+2,
		fmt.Sprintf("echo=%d/4 adm_udp=%d dns_refused=%d->%d dns_overflow=%d->%d refused_adm=%d->%d",
			got, s.admUDP, b.dnsRefused, s.dnsRefused, b.dnsOverflow, s.dnsOverflow, b.udpRefusedAdm, s.udpRefusedAdm))

	setFakeAvailKB(20 * 1024)
	time.Sleep(100 * time.Millisecond)
	got, b, s = burst("d6o2")
	check("D6 open again: the overflow passes again",
		got == 4 && s.admUDP == admitOpen && s.dnsOverflow == b.dnsOverflow+2,
		fmt.Sprintf("echo=%d/4 adm_udp=%d dns_overflow=%d->%d", got, s.admUDP, b.dnsOverflow, s.dnsOverflow))
	check("D6 probe off", probeOff() == 0 && setProbeTypes(sessUDP|sessTCP, sessUDP|sessTCP) == 0, "")
	r.quit("dns-overflow")
}

// O. Запрос сверх пула, ставший обычной сессией UDP, живёт по таймауту пула (O1) и не попадает под
// защиту evict-protect-idle (O2). max-session-count и колбэк памяти к нему применяются как раньше (D6).
func partDNSOverflowSession() {
	// Пул 1 на 9.9.9.9 с таймаутом 2 с, read-write-timeout обычного UDP 30 с. Таблица на 2, защищён
	// поток, говоривший через 1 с после создания и молчащий меньше 2 с.
	conf := "  max-session-count: 2\n  evict-protect-idle: 2000\n" +
		"  dns-priority-sessions: 1\n  dns-priority-timeout: 2000\n  dns-priority-addresses: '9.9.9.9'\n"
	var r *rig
	// Пул занят молодым запросом без ответа, следующий запрос идёт мимо пула.
	overflow := func(tag string) (*gonet.UDPConn, bool, sessionStats, sessionStats) {
		hold := r.openUDPTo([4]byte{9, 9, 9, 9}, 53)
		hold.Write([]byte("NOREPLY-" + tag))
		time.Sleep(50 * time.Millisecond)
		before := mustStats()
		ov := r.openUDPTo([4]byte{9, 9, 9, 9}, 53)
		ok := udpEcho(ov, tag)
		return ov, ok, before, mustStats()
	}

	r = newRig(cfg(conf))
	_, ok, b, s := overflow("o1")
	check("O1 a query over a full pool starts as an ordinary udp session",
		ok && s.dnsOverflow == b.dnsOverflow+1 && s.udpLive == b.udpLive+1,
		fmt.Sprintf("echo=%v overflow=%d->%d udp_live=%d->%d", ok, b.dnsOverflow, s.dnsOverflow, b.udpLive, s.udpLive))
	time.Sleep(2700 * time.Millisecond)
	s = mustStats()
	check("O1 that session times out after dns-priority-timeout, not read-write-timeout",
		s.udpLive == b.udpLive && s.dnsLive == 0, fmt.Sprintf("udp_live=%d dns_live=%d", s.udpLive, s.dnsLive))
	r.quit("dns-overflow-timeout")

	r = newRig(cfg(conf))
	plain := r.openUDP(1, 25400)[0]
	pok := udpEcho(plain, "o2p")
	ov, ok, _, _ := overflow("o2")
	s = mustStats()
	check("O2 an ordinary flow and the overflow session fill the table",
		ok && pok && s.udpLive == 2, fmt.Sprintf("echo=%v/%v udp_live=%d", pok, ok, s.udpLive))
	// Оба говорят через 1.4 с после создания, переполнение последним: давнее активен обычный поток.
	time.Sleep(1400 * time.Millisecond)
	pok = udpEcho(plain, "o2p2")
	ok = udpEcho(ov, "o2v2")
	b = mustStats()
	nok := udpEcho(r.openUDP(1, 25500)[0], "o2n")
	s = mustStats()
	check("O2 a new flow takes the place of the overflow session, the protected flow stays although less recently active",
		pok && ok && nok && s.udpEvicted == b.udpEvicted+1 && s.udpLive == 2 && s.protectedLive == 1 && stillLive(plain, "o2p3"),
		fmt.Sprintf("echo=%v/%v/%v evicted=%d->%d udp_live=%d protected=%d", pok, ok, nok, b.udpEvicted, s.udpEvicted, s.udpLive, s.protectedLive))
	r.quit("dns-overflow-protect")
}

// F. Правки по ревью пула: ответившая сессия без ждущего запроса уступает место сразу, с ждущим -
// через секунду (F1); пустой список адресов выключает пул, "any" - любой адрес (F2); размер и
// таймаут в пределах (F8); маска relieve (F5).
func partDNSReview() {
	conf := "  dns-priority-sessions: 1\n  dns-priority-timeout: 4000\n  dns-priority-addresses: '9.9.9.9'\n"
	r := newRig(cfg(conf))
	long := r.openUDPTo([4]byte{9, 9, 9, 9}, 53)
	check("F1 long resolver socket answers", udpEcho(long, "f1a"), "")
	time.Sleep(1200 * time.Millisecond)
	check("F1 long resolver socket keeps talking", udpEcho(long, "f1b"), "")
	s := mustStats()
	q := r.openUDPTo([4]byte{9, 9, 9, 9}, 53)
	qok := udpEcho(q, "f1q")
	s2 := mustStats()
	check("F1 an answered session with no query waiting gives up its place at once",
		qok && s2.dnsEvicted == s.dnsEvicted+1 && s2.dnsOverflow == s.dnsOverflow,
		fmt.Sprintf("echo=%v evicted=%d->%d overflow=%d->%d", qok, s.dnsEvicted, s2.dnsEvicted, s.dnsOverflow, s2.dnsOverflow))
	// q ответила, теперь шлёт запрос без ответа: секунду её место держится.
	q.Write([]byte("NOREPLY-f1"))
	time.Sleep(50 * time.Millisecond)
	s = mustStats()
	q2 := r.openUDPTo([4]byte{9, 9, 9, 9}, 53)
	q2ok := udpEcho(q2, "f1q2")
	s2 = mustStats()
	check("F1 an answered session with a query waiting keeps its place, the query goes the ordinary way",
		q2ok && s2.dnsEvicted == s.dnsEvicted && s2.dnsOverflow == s.dnsOverflow+1,
		fmt.Sprintf("echo=%v evicted=%d->%d overflow=%d->%d", q2ok, s.dnsEvicted, s2.dnsEvicted, s.dnsOverflow, s2.dnsOverflow))
	time.Sleep(1200 * time.Millisecond)
	s = mustStats()
	q3 := r.openUDPTo([4]byte{9, 9, 9, 9}, 53)
	q3ok := udpEcho(q3, "f1q3")
	s2 = mustStats()
	check("F1 a query waiting longer than a second no longer keeps the place",
		q3ok && s2.dnsEvicted == s.dnsEvicted+1 && s2.dnsOverflow == s.dnsOverflow,
		fmt.Sprintf("echo=%v evicted=%d->%d overflow=%d->%d", q3ok, s.dnsEvicted, s2.dnsEvicted, s.dnsOverflow, s2.dnsOverflow))
	check("F5 relieve rejects unknown session kinds", relieve(reliefUDP|4, 0, 0) == -1, "")
	r.quit("dns-review")

	r = newRig(cfg("  dns-priority-sessions: 1\n  dns-priority-addresses: 'any'\n"))
	s = mustStats()
	aok := udpEcho(r.openUDPTo([4]byte{1, 2, 3, 4}, 53), "f2any")
	s2 = mustStats()
	check("F2 any in config sends port 53 of any address to the pool",
		aok && s.dnsCap == 1 && s2.dnsCreated == 1 && s2.udpCreated == 0,
		fmt.Sprintf("echo=%v dns_cap=%d dns_created=%d udp_created=%d", aok, s.dnsCap, s2.dnsCreated, s2.udpCreated))
	r.quit("dns-any")

	for _, c := range []struct{ name, conf string }{
		{"F2 empty address list in config turns the pool off", "  dns-priority-sessions: 2\n  dns-priority-addresses: ''\n"},
		{"F2 an ipv6 address in the list turns the pool off", "  dns-priority-sessions: 2\n  dns-priority-addresses: '1.1.1.1,::1'\n"},
		{"F8 oversized pool in config turns the pool off", "  dns-priority-sessions: 64\n  dns-priority-addresses: '9.9.9.9'\n"},
		{"F8 pool timeout below a second in config turns the pool off",
			"  dns-priority-sessions: 1\n  dns-priority-timeout: 500\n  dns-priority-addresses: '9.9.9.9'\n"},
	} {
		r = newRig(cfg(c.conf))
		s = mustStats()
		check(c.name, s.dnsCap == 0, fmt.Sprintf("dns_cap=%d", s.dnsCap))
		r.quit("dns-off")
	}
}

func main() {
	flag.Parse()
	os.Remove(*logPath)
	partR8()
	partTable()
	partProtect()
	partProtectHalf()
	partYoung()
	partProbe()
	partProbeProtect()
	partReview()
	partDNS()
	partDNSOverflow()
	partDNSOverflowSession()
	partDNSReview()
	fmt.Printf("SUMMARY pass=%d fail=%d\n", passed, failed)
	if failed > 0 {
		os.Exit(1)
	}
}
