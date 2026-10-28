// Смоук hev кита (срез macosx arm64) с серией r9: gVisor netstack <-> socketpair (формат utun) <-> hev <-> socksd.
// Часть 1 - проверки r8: relieve, гонка relieve с остановкой.
// Часть 3 - пул DNS (0009, 0011): D - пул под потолком UDP, HOLD и CLOSED, адреса из списка и мимо
// него, вытеснение и отказ в полном пуле, свой таймаут, сеттер, старый размер статистики; D6 - запрос
// сверх полного пула идёт обычным путём UDP; F - правки по ревью пула.
// Часть 2 - guard: потолки из конфига, вытеснение молчащих, отказ TCP сбросом, внешний приём,
// колбэк памяти (CLOSED / HOLD / OPEN с гистерезисом, типы колбэка), защита установившихся из
// ключей конфига (патч 0008) и повторное чтение конфига на перезапуске, размер статистики.
// Число сессий в части 1 читается из строки лога hev "relieve ... udp U tcp T of N", в части 2 -
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

func partGuard() {
	check("stats refuse a too small size", statsWithSize(8) == -1, "")

	// G1. Потолки из конфига: UDP 4, TCP 2, вытеснение UDP после 1 с тишины.
	caps := "  udp-max-sessions: 4\n  tcp-max-sessions: 2\n  udp-evict-min-idle: 1000\n  tcp-evict-min-idle: 60000\n" +
		"  udp-queue-frames: 64\n  udp-queue-total-frames: 1024\n"
	r := newRig(cfg(caps))
	s := mustStats()
	check("G1 caps come from config", s.udpCap == 4 && s.tcpCap == 2, fmt.Sprintf("udp_cap=%d tcp_cap=%d", s.udpCap, s.tcpCap))

	first := r.openUDP(4, 22000)
	check("G1 4 udp flows echo", allEcho(first, "g1"), "")
	extra := r.openUDP(2, 22100)
	got := burstEcho(extra, "g1x")
	s = mustStats()
	check("G1 flows over the cap are refused while others are active", got == 0 && s.udpLive == 4 && s.udpRefused >= 2,
		fmt.Sprintf("echo=%d live=%d refused=%d", got, s.udpLive, s.udpRefused))
	check("G1 live flows still echo", allEcho(first, "g1b"), "")

	// G2. После 1 с тишины новая сессия вытесняет самую давно молчащую.
	time.Sleep(1200 * time.Millisecond)
	evictor := r.openUDP(1, 22200)
	ok := udpEcho(evictor[0], "g2")
	s = mustStats()
	check("G2 new flow replaces a silent one", ok && s.udpLive == 4 && s.udpEvicted >= 1,
		fmt.Sprintf("echo=%v live=%d evicted=%d", ok, s.udpLive, s.udpEvicted))

	// G3. Потолок TCP: третье соединение получает сброс, первые два живы.
	t1, t2 := r.dialTCP(), r.dialTCP()
	check("G3 two tcp under the cap echo", t1 != nil && t2 != nil && tcpEcho(t1, "t1") && tcpEcho(t2, "t2"), "")
	t3 := r.dialTCP()
	t3ok := t3 != nil && tcpEcho(t3, "t3")
	s = mustStats()
	check("G3 tcp over the cap is reset", !t3ok && s.tcpRefused >= 1 && s.tcpLive == 2,
		fmt.Sprintf("echo=%v refused=%d live=%d", t3ok, s.tcpRefused, s.tcpLive))
	check("G3 tcp under the cap keeps working", tcpEcho(t1, "t1b") && tcpEcho(t2, "t2b"), "")

	// G4. Внешний приём: CLOSED для UDP закрывает новые, живые работают, OPEN возвращает.
	check("G4 set_admission(udp, closed)", setAdmission(sessUDP, admitClosed) == 0, "")
	time.Sleep(1200 * time.Millisecond)
	blocked := r.openUDP(1, 22300)
	bok := udpEcho(blocked[0], "g4")
	s = mustStats()
	check("G4 closed admission refuses a new udp flow even with silent ones", !bok && s.admUDP == admitClosed && s.udpRefusedAdm >= 1,
		fmt.Sprintf("echo=%v adm_udp=%d refused_adm=%d", bok, s.admUDP, s.udpRefusedAdm))
	check("G4 live udp flow echoes while closed", udpEcho(evictor[0], "g4live"), "")
	check("G4 set_admission(udp, open)", setAdmission(sessUDP, admitOpen) == 0, "")
	time.Sleep(1200 * time.Millisecond)
	reopened := r.openUDP(1, 22400)
	check("G4 open admission lets a new flow in again", udpEcho(reopened[0], "g4open"), "")
	check("G4 invalid admission is rejected", setAdmission(sessUDP, 3) == -1 && setAdmission(4, admitOpen) == -1, "")

	// G5. Колбэк памяти: HOLD только UDP, CLOSED UDP и TCP, пороги 12 / 8 МБ, гистерезис 2 МБ.
	check("G5 raise caps for the probe test", setSessionCap(sessUDP, 16, 1000) == 0 && setSessionCap(sessTCP, 16, 60000) == 0, "")
	check("G5 probe types hold=udp close=all", setProbeTypes(sessUDP, sessUDP|sessTCP) == 0, "")
	setFakeAvailKB(5 * 1024)
	check("G5 probe on", probeOn(0, 12*1024, 8*1024, 2*1024, 1000, 0) == 0, "")
	time.Sleep(100 * time.Millisecond)
	c1 := r.openUDP(1, 22500)
	c1ok := udpEcho(c1[0], "g5c")
	t4 := r.dialTCP()
	t4ok := t4 != nil && tcpEcho(t4, "t4")
	s = mustStats()
	check("G5 below close: new udp and tcp refused", !c1ok && !t4ok && s.admUDP == admitClosed && s.admTCP == admitClosed,
		fmt.Sprintf("udp=%v tcp=%v adm=%d/%d probe_kb=%d", c1ok, t4ok, s.admUDP, s.admTCP, s.lastProbeKB))
	check("G5 probe result is reported", s.lastProbeKB == 5*1024 && probeCalls() > 0,
		fmt.Sprintf("probe_kb=%d calls=%d", s.lastProbeKB, probeCalls()))

	setFakeAvailKB(11 * 1024)
	time.Sleep(100 * time.Millisecond)
	t5 := r.dialTCP()
	t5ok := t5 != nil && tcpEcho(t5, "t5")
	s = mustStats()
	check("G5 between thresholds after closed: udp hold, tcp open", t5ok && s.admUDP == admitHold && s.admTCP == admitOpen,
		fmt.Sprintf("tcp=%v adm=%d/%d", t5ok, s.admUDP, s.admTCP))
	// Без живых UDP в HOLD новой сессии не на чьё место встать, хотя до потолка 16 далеко.
	_, relieved := relieveAndWait(reliefUDP, 0, 0)
	time.Sleep(300 * time.Millisecond)
	s = mustStats()
	check("G5 relieve closes all udp before the hold test", relieved && s.udpLive == 0, fmt.Sprintf("live=%d", s.udpLive))
	refusedAdmBefore := s.udpRefusedAdm
	h1 := r.openUDP(1, 22600)
	h1ok := udpEcho(h1[0], "g5h")
	s = mustStats()
	check("G5 hold refuses udp growth below the cap", !h1ok && s.udpRefusedAdm > refusedAdmBefore,
		fmt.Sprintf("echo=%v live=%d refused_adm=%d->%d", h1ok, s.udpLive, refusedAdmBefore, s.udpRefusedAdm))

	setFakeAvailKB(13 * 1024)
	time.Sleep(100 * time.Millisecond)
	h2 := r.openUDP(1, 22700)
	h2ok := udpEcho(h2[0], "g5h2")
	s = mustStats()
	check("G5 hysteresis keeps hold just above the hold threshold", !h2ok && s.admUDP == admitHold,
		fmt.Sprintf("echo=%v adm_udp=%d", h2ok, s.admUDP))

	setFakeAvailKB(20 * 1024)
	time.Sleep(100 * time.Millisecond)
	o1 := r.openUDP(1, 22800)
	o1ok := udpEcho(o1[0], "g5o")
	s = mustStats()
	check("G5 plenty of memory: open again", o1ok && s.admUDP == admitOpen && s.admTCP == admitOpen,
		fmt.Sprintf("echo=%v adm=%d/%d", o1ok, s.admUDP, s.admTCP))
	check("G5 probe off", probeOff() == 0 && setProbeTypes(sessUDP|sessTCP, sessUDP|sessTCP) == 0, "")
	setFakeAvailKB(1024)
	time.Sleep(100 * time.Millisecond)
	o2 := r.openUDP(1, 22900)
	check("G5 probe off ignores the probe", udpEcho(o2[0], "g5off"), "")
	r.quit("guard")

	// G6. Защита установившихся из ключей конфига (патч 0008) и повторное чтение конфига:
	// потолок 16 из рантайма должен смениться на 2 из конфига.
	protect := "  udp-max-sessions: 2\n  udp-evict-min-idle: 1000\n  udp-evict-protect-age: 500\n  udp-evict-protect-idle: 5000\n"
	r = newRig(cfg(protect))
	s = mustStats()
	check("G6 restart applies config caps again and resets counters", s.udpCap == 2 && s.tcpCap == 0 && s.udpCreated == 0,
		fmt.Sprintf("udp_cap=%d tcp_cap=%d created=%d", s.udpCap, s.tcpCap, s.udpCreated))
	pair := r.openUDP(2, 23000)
	check("G6 2 flows echo", allEcho(pair, "g6"), "")
	time.Sleep(1200 * time.Millisecond)
	p1 := r.openUDP(1, 23100)
	p1ok := udpEcho(p1[0], "g6p")
	s = mustStats()
	check("G6 answered flows older than 0.5 s are not evicted after 1 s of silence", !p1ok && s.udpEvicted == 0 && s.udpRefused >= 1,
		fmt.Sprintf("echo=%v evicted=%d refused=%d", p1ok, s.udpEvicted, s.udpRefused))
	check("G6 protection off at runtime", setEvictProtect(sessUDP, 0, 0) == 0, "")
	p2 := r.openUDP(1, 23200)
	p2ok := udpEcho(p2[0], "g6q")
	s = mustStats()
	check("G6 without protection the silent flow is evicted", p2ok && s.udpEvicted >= 1,
		fmt.Sprintf("echo=%v evicted=%d", p2ok, s.udpEvicted))
	r.quit("protect")
}

// Проверки правок по ревью патчей: H3 разбор ключей, K5 пороги колбэка, H4 причина отказа в HOLD,
// H5 и K6 свежесть оценки памяти в статистике.
func partReview() {
	bad := "  udp-max-sessions: 64abc\n  tcp-max-sessions: -1\n"
	r := newRig(cfg(bad))
	s := mustStats()
	check("H3 malformed caps fall back to no cap", s.udpCap == 0 && s.tcpCap == 0,
		fmt.Sprintf("udp_cap=%d tcp_cap=%d", s.udpCap, s.tcpCap))
	r.quit("bad-config")

	check("K5 close above hold is rejected", probeOn(0, 8*1024, 12*1024, 0, 0, 0) == -1, "")
	check("K5 negative hysteresis is rejected", probeOn(0, 12*1024, 8*1024, -1, 0, 0) == -1, "")

	caps := "  udp-max-sessions: 2\n  udp-evict-min-idle: 60000\n"
	r = newRig(cfg(caps))
	pair := r.openUDP(2, 24000)
	check("H4 2 flows echo at the cap", allEcho(pair, "h4"), "")
	setFakeAvailKB(10 * 1024)
	check("H4 probe on, hold", probeOn(0, 12*1024, 8*1024, 0, 0, 0) == 0, "")
	time.Sleep(100 * time.Millisecond)
	before := mustStats()
	extra := r.openUDP(1, 24100)
	eok := udpEcho(extra[0], "h4x")
	s = mustStats()
	check("H4 refusal at the cap in hold is not counted as memory",
		!eok && s.admUDP == admitHold && s.udpRefused > before.udpRefused && s.udpRefusedAdm == before.udpRefusedAdm,
		fmt.Sprintf("echo=%v adm=%d refused=%d->%d refused_adm=%d->%d", eok, s.admUDP,
			before.udpRefused, s.udpRefused, before.udpRefusedAdm, s.udpRefusedAdm))

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
	_, ok := stats()
	check("W4 stats are unavailable once the tunnel has stopped", !ok, "")
}

func strp(s string) *string { return &s }

// D. Пул DNS (0009): UDP на 53 к адресам из списка идёт в свой пул мимо потолка UDP и колбэка памяти.
func partDNS() {
	// Потолок UDP 4, а молчащий поток вытесняется только после 60 с тишины: новый обычный UDP получает отказ.
	// Таймаут пула 4 с: шаги D1-D3 укладываются в 2 с, D4 ждёт его истечения.
	conf := "  udp-max-sessions: 4\n  udp-evict-min-idle: 60000\n" +
		"  dns-priority-sessions: 2\n  dns-priority-timeout: 4000\n  dns-priority-addresses: '9.9.9.9,8.8.8.8'\n"
	r := newRig(cfg(conf))
	ret, size, untouched := statsCallerWithSize(statsGuardSize())
	check("D0 stats accept the size of a caller without dns fields and write nothing past it",
		ret == 0 && size == statsGuardSize() && untouched, fmt.Sprintf("ret=%d size=%d/%d untouched=%v", ret, size, statsGuardSize(), untouched))
	check("D0 stats refuse a size below that", statsWithSize(statsGuardSize()-1) == -1, "")

	s := mustStats()
	check("D1 pool comes from config", s.dnsCap == 2 && s.dnsLive == 0, fmt.Sprintf("dns_cap=%d dns_live=%d", s.dnsCap, s.dnsLive))
	fill := r.openUDP(4, 24000)
	check("D1 4 udp flows fill the cap", allEcho(fill, "d1"), "")
	time.Sleep(300 * time.Millisecond)
	extra := r.openUDP(1, 24100)
	eok := udpEchoWithin(extra[0], "d1x", refusedWait)
	s = mustStats()
	check("D1 control: a new udp flow over a cap of silent flows is refused", !eok && s.udpLive == 4 && s.udpRefused >= 1,
		fmt.Sprintf("echo=%v live=%d refused=%d", eok, s.udpLive, s.udpRefused))
	q1 := r.openUDPTo([4]byte{9, 9, 9, 9}, 53)
	q1ok := udpEcho(q1, "d1q")
	s = mustStats()
	check("D1 dns to a listed resolver passes the full udp cap and does not count in it",
		q1ok && s.dnsLive == 1 && s.dnsCreated == 1 && s.udpLive == 4,
		fmt.Sprintf("echo=%v dns_live=%d dns_created=%d udp_live=%d", q1ok, s.dnsLive, s.dnsCreated, s.udpLive))
	refused := s.udpRefused
	u1 := r.openUDPTo([4]byte{1, 1, 1, 1}, 53)
	u1ok := udpEchoWithin(u1, "d1u", refusedWait)
	s = mustStats()
	check("D1 port 53 of an unlisted address is ordinary udp and is refused at the cap",
		!u1ok && s.udpRefused > refused && s.dnsCreated == 1,
		fmt.Sprintf("echo=%v udp_refused=%d->%d dns_created=%d", u1ok, refused, s.udpRefused, s.dnsCreated))

	// D2. Колбэк памяти, пороги 12 / 8 МБ: 11 МБ - HOLD для UDP, 5 МБ - CLOSED.
	setFakeAvailKB(11 * 1024)
	check("D2 probe on, hold=udp close=all, 11 MB left",
		setProbeTypes(sessUDP, sessUDP|sessTCP) == 0 && probeOn(0, 12*1024, 8*1024, 2*1024, 1000, 0) == 0, "")
	time.Sleep(100 * time.Millisecond)
	// Живых UDP ровно потолок, поэтому отказ считается отказом потолка, а не памяти (H4).
	refusedBefore, refusedAdm := s.udpRefused, s.udpRefusedAdm
	h1 := r.openUDP(1, 24200)
	h1ok := udpEchoWithin(h1[0], "d2h", refusedWait)
	s = mustStats()
	check("D2 control: hold refuses a new udp flow at the cap as a cap refusal",
		!h1ok && s.admUDP == admitHold && s.udpRefused > refusedBefore && s.udpRefusedAdm == refusedAdm,
		fmt.Sprintf("echo=%v adm_udp=%d refused=%d->%d refused_adm=%d->%d", h1ok, s.admUDP, refusedBefore, s.udpRefused, refusedAdm, s.udpRefusedAdm))
	q2 := r.openUDPTo([4]byte{8, 8, 8, 8}, 53)
	q2ok := udpEcho(q2, "d2q")
	s = mustStats()
	check("D2 dns to a listed resolver passes in hold", q2ok && s.dnsLive == 2 && s.dnsCreated == 2,
		fmt.Sprintf("echo=%v dns_live=%d dns_created=%d", q2ok, s.dnsLive, s.dnsCreated))
	setFakeAvailKB(5 * 1024)
	time.Sleep(100 * time.Millisecond)
	c1 := r.openUDP(1, 24300)
	c1ok := udpEchoWithin(c1[0], "d2c", refusedWait)
	s = mustStats()
	check("D2 control: closed refuses a new udp flow", !c1ok && s.admUDP == admitClosed,
		fmt.Sprintf("echo=%v adm_udp=%d", c1ok, s.admUDP))
	q3 := r.openUDPTo([4]byte{9, 9, 9, 9}, 53)
	q3ok := udpEcho(q3, "d2q3")
	s = mustStats()
	check("D2 in closed a full pool gives up an answered session for a new query",
		q3ok && s.dnsLive == 2 && s.dnsCreated == 3 && s.dnsEvicted == 1,
		fmt.Sprintf("echo=%v dns_live=%d created=%d evicted=%d", q3ok, s.dnsLive, s.dnsCreated, s.dnsEvicted))

	// D3. Три запроса разом после секунды тишины: первые два вытесняют отвеченные, третий застаёт
	// пул из двух молодых без ответа и идёт обычным путём, а там потолок UDP полон.
	time.Sleep(1200 * time.Millisecond)
	before := s
	burst := []*gonet.UDPConn{
		r.openUDPTo([4]byte{9, 9, 9, 9}, 53), r.openUDPTo([4]byte{8, 8, 8, 8}, 53), r.openUDPTo([4]byte{9, 9, 9, 9}, 53),
	}
	got := burstEcho(burst, "d3")
	s = mustStats()
	check("D3 a pool full of young unanswered queries does not take the next one",
		got == 2 && s.dnsRefused == before.dnsRefused+1 && s.dnsEvicted == before.dnsEvicted+2,
		fmt.Sprintf("echo=%d/3 refused=%d->%d evicted=%d->%d", got, before.dnsRefused, s.dnsRefused, before.dnsEvicted, s.dnsEvicted))

	// D4. У сессий пула свой таймаут 4 с, обычные UDP живут по read-write-timeout 30 с.
	time.Sleep(5 * time.Second)
	s = mustStats()
	check("D4 pool sessions time out after dns-priority-timeout, ordinary udp stays", s.dnsLive == 0 && s.udpLive == 4,
		fmt.Sprintf("dns_live=%d udp_live=%d", s.dnsLive, s.udpLive))
	check("D4 probe off", probeOff() == 0 && setProbeTypes(sessUDP|sessTCP, sessUDP|sessTCP) == 0, "")

	// D5. Сеттер: пул 1 на 1.1.1.1, список с IPv6 отклоняется целиком.
	check("D5 set_dns_priority(1, default timeout, 1.1.1.1)", setDnsPriority(1, 0, strp("1.1.1.1")) == 0, "")
	check("D5 invalid list is rejected and changes nothing",
		setDnsPriority(4, 0, strp("1.1.1.1,::1")) == -1 && mustStats().dnsCap == 1, "")
	created := mustStats().dnsCreated
	u2 := r.openUDPTo([4]byte{1, 1, 1, 1}, 53)
	u2ok := udpEcho(u2, "d5u")
	s = mustStats()
	check("D5 the newly listed address goes to the pool past the full udp cap", u2ok && s.dnsCreated == created+1,
		fmt.Sprintf("echo=%v dns_created=%d->%d", u2ok, created, s.dnsCreated))
	refused = s.udpRefused
	q4 := r.openUDPTo([4]byte{9, 9, 9, 9}, 53)
	q4ok := udpEchoWithin(q4, "d5q", refusedWait)
	s = mustStats()
	check("D5 the address dropped from the list is ordinary udp again", !q4ok && s.udpRefused > refused,
		fmt.Sprintf("echo=%v udp_refused=%d->%d", q4ok, refused, s.udpRefused))
	r.quit("dns")
}

// D6. Запрос, не влезший в полный пул молодых без ответа (0011), идёт обычным путём UDP: при открытом
// приёме стартует обычной сессией, в HOLD и CLOSED колбэка получает отказ, как любой новый UDP.
func partDNSOverflow() {
	// Потолок UDP 8 с запасом, пул 2 на 9.9.9.9: четыре запроса разом - два в пул, два мимо него.
	conf := "  udp-max-sessions: 8\n  udp-evict-min-idle: 60000\n" +
		"  dns-priority-sessions: 2\n  dns-priority-timeout: 4000\n  dns-priority-addresses: '9.9.9.9'\n"
	r := newRig(cfg(conf))
	ret, size, untouched := statsCallerWithSize(statsPoolSize())
	check("D6 stats accept the size of a caller without dns_overflow and write nothing past it",
		ret == 0 && size == statsPoolSize() && untouched, fmt.Sprintf("ret=%d size=%d untouched=%v", ret, size, untouched))

	burst := func(tag string) (int, sessionStats, sessionStats) {
		// Ответившие сессии пула вытесняются только после секунды тишины (F1).
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
	check("D6 hold: queries over a full pool are refused like new udp",
		got == 2 && s.admUDP == admitHold && s.dnsRefused == b.dnsRefused+2 && s.dnsOverflow == b.dnsOverflow &&
			s.udpRefusedAdm == b.udpRefusedAdm+2,
		fmt.Sprintf("echo=%d/4 adm_udp=%d dns_refused=%d->%d dns_overflow=%d->%d refused_adm=%d->%d",
			got, s.admUDP, b.dnsRefused, s.dnsRefused, b.dnsOverflow, s.dnsOverflow, b.udpRefusedAdm, s.udpRefusedAdm))

	setFakeAvailKB(5 * 1024)
	time.Sleep(100 * time.Millisecond)
	got, b, s = burst("d6c")
	check("D6 closed: queries over a full pool are refused like new udp",
		got == 2 && s.admUDP == admitClosed && s.dnsRefused == b.dnsRefused+2 && s.dnsOverflow == b.dnsOverflow,
		fmt.Sprintf("echo=%d/4 adm_udp=%d dns_refused=%d->%d dns_overflow=%d->%d",
			got, s.admUDP, b.dnsRefused, s.dnsRefused, b.dnsOverflow, s.dnsOverflow))

	setFakeAvailKB(20 * 1024)
	time.Sleep(100 * time.Millisecond)
	got, b, s = burst("d6o2")
	check("D6 open again: the overflow passes again",
		got == 4 && s.admUDP == admitOpen && s.dnsOverflow == b.dnsOverflow+2,
		fmt.Sprintf("echo=%d/4 adm_udp=%d dns_overflow=%d->%d", got, s.admUDP, b.dnsOverflow, s.dnsOverflow))
	check("D6 probe off", probeOff() == 0 && setProbeTypes(sessUDP|sessTCP, sessUDP|sessTCP) == 0, "")
	r.quit("dns-overflow")
}

// F. Правки по ревью пула: ответивший долгий сокет не вытесняется, пока говорит (F1); пустой список
// адресов выключает пул, "any" - любой адрес (F2); размер и таймаут в пределах (F8); маска relieve (F5).
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
	check("F1 a talking answered session is not evicted, the query goes the ordinary way",
		qok && s2.dnsEvicted == s.dnsEvicted && s2.dnsOverflow == s.dnsOverflow+1,
		fmt.Sprintf("echo=%v evicted=%d->%d overflow=%d->%d", qok, s.dnsEvicted, s2.dnsEvicted, s.dnsOverflow, s2.dnsOverflow))
	check("F5 relieve rejects unknown session kinds", relieve(reliefUDP|4, 0, 0) == -1, "")
	check("F8 pool size over 32 is rejected", setDnsPriority(64, 0, nil) == -1, "")
	check("F8 pool timeout below a second is rejected", setDnsPriority(1, 500, nil) == -1, "")
	check("F2 empty list is rejected by the setter", setDnsPriority(1, 0, strp("")) == -1, "")
	check("F2 any is accepted", setDnsPriority(1, 0, strp("any")) == 0, "")
	r.quit("dns-review")

	r = newRig(cfg("  dns-priority-sessions: 2\n  dns-priority-addresses: ''\n"))
	s = mustStats()
	check("F2 empty address list in config turns the pool off", s.dnsCap == 0, fmt.Sprintf("dns_cap=%d", s.dnsCap))
	r.quit("dns-empty")

	r = newRig(cfg("  dns-priority-sessions: 64\n  dns-priority-addresses: '9.9.9.9'\n"))
	s = mustStats()
	check("F8 oversized pool in config turns the pool off", s.dnsCap == 0, fmt.Sprintf("dns_cap=%d", s.dnsCap))
	r.quit("dns-oversized")
}

func main() {
	flag.Parse()
	os.Remove(*logPath)
	partR8()
	partGuard()
	partReview()
	partDNS()
	partDNSOverflow()
	partDNSReview()
	fmt.Printf("SUMMARY pass=%d fail=%d\n", passed, failed)
	if failed > 0 {
		os.Exit(1)
	}
}
