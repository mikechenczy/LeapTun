package main

import (
	"LeapTun/dll"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/gorilla/websocket"
	"github.com/inancgumus/screen"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"log"
	"net"
	"os/exec"
	"runtime"
	"sync"
	"time"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/tun"
)

const tunPacketOffset = 14
const maxLimit = 1 << 23

var (
	tunStarted = false
	ip         = "10.0.0.0"
	stop       = make(chan struct{})
	wg         sync.WaitGroup
	stopOnce   sync.Once
	devName    string
	dev        tun.Device
	c          *Convertor
)

func setIPv4Addr(ipAddr string) error {
	if !tunStarted {
		return fmt.Errorf("TUN尚未启动")
	}
	ip = ipAddr
	switch runtime.GOOS {
	case "windows":
		// Windows 使用 netsh
		cmd := exec.Command("netsh", "interface", "ipv4", "set", "address",
			fmt.Sprintf("name=%s", devName), "static", ip, "255.255.255.0")
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("Windows netsh 失败: %v, 输出: %s", err, string(out))
		}
		return nil

	default:
		link, err := netlink.LinkByName(devName)
		if err != nil {
			return fmt.Errorf("查找网卡失败: %v", err)
		}

		addrStr := fmt.Sprintf("%s/%s", ip, "24")
		addr, err := netlink.ParseAddr(addrStr)
		if err != nil {
			return fmt.Errorf("解析地址失败: %v", err)
		}

		// 先清理旧的 IPv4 地址
		addrs, err := netlink.AddrList(link, 2)
		if err != nil {
			return fmt.Errorf("获取旧地址失败: %v", err)
		}
		for _, a := range addrs {
			_ = netlink.AddrDel(link, &a)
		}

		// 添加新的
		if err := netlink.AddrAdd(link, addr); err != nil {
			return fmt.Errorf("添加地址失败: %v", err)
		}

		if err := netlink.LinkSetUp(link); err != nil {
			return fmt.Errorf("启动网卡失败: %v", err)
		}

		return nil
	}
}

func getDstIP(pkt []byte) (dstIP string) {
	if len(pkt) < 20 {
		return ""
	}
	if pkt[0]>>4 != 4 {
		return ""
	}
	ipDst := net.IP(pkt[16:20]).To4()
	if ipDst == nil {
		return ""
	}
	return ipDst.String()
}

func isSameSubnet(ip1Str, ip2Str string) bool {
	ip1 := net.ParseIP(ip1Str).To4()
	ip2 := net.ParseIP(ip2Str).To4()
	if ip1 == nil || ip2 == nil {
		return false
	}

	mask := net.CIDRMask(24, 32) // /24
	network1 := ip1.Mask(mask)
	network2 := ip2.Mask(mask)

	return network1.Equal(network2)
}

type ConnMap struct {
	mu          sync.Mutex
	connWriters map[stack.TransportEndpointID]*ConnHandler
}

func (cm *ConnMap) Set(id stack.TransportEndpointID, connWriter *ConnHandler) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.connWriters[id] = connWriter
}

func (cm *ConnMap) Get(id stack.TransportEndpointID) (*ConnHandler, bool) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	c, ok := cm.connWriters[id]
	return c, ok
}

func (cm *ConnMap) Delete(id stack.TransportEndpointID) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	delete(cm.connWriters, id)
}

func (cm *ConnMap) Keys() []stack.TransportEndpointID {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	keys := make([]stack.TransportEndpointID, 0, len(cm.connWriters))
	for k := range cm.connWriters {
		keys = append(keys, k)
	}
	return keys
}

var cmServer = &ConnMap{
	connWriters: make(map[stack.TransportEndpointID]*ConnHandler),
}

var cmClient = &ConnMap{
	connWriters: make(map[stack.TransportEndpointID]*ConnHandler),
}

func decodeEndpointID(b []byte) *stack.TransportEndpointID {
	if len(b) < 12 {
		log.Println("Invalid byte length for EndpointID")
		return nil
	}

	id := &stack.TransportEndpointID{
		LocalAddress:  tcpip.AddrFrom4Slice(b[0:4]),
		RemoteAddress: tcpip.AddrFrom4Slice(b[4:8]),
		LocalPort:     binary.BigEndian.Uint16(b[8:10]),
		RemotePort:    binary.BigEndian.Uint16(b[10:12]),
	}

	return id
}

var allClosed bool
var closeLocker sync.Mutex

func closeAll(conn *websocket.Conn) {
	closeLocker.Lock()
	defer closeLocker.Unlock()
	if allClosed {
		return
	}
	allClosed = true
	c.Close()
	_ = dev.Close()
	_ = conn.Close()
	close(wsWriteQueue)
	for _, id := range cmClient.Keys() {
		conn, ok := cmClient.Get(id)
		if !ok {
			continue
		}
		cmClient.Delete(id)
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = conn.Close()
		}()
	}
	for _, id := range cmServer.Keys() {
		conn, ok := cmServer.Get(id)
		if !ok {
			continue
		}
		cmServer.Delete(id)
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = conn.Close()
		}()
	}
}

func run(wsConn *websocket.Conn) {
	allClosed = false
	dllPath, err := dll.EnsureWintunDLL()
	if err != nil {
		panic(err)
	}
	fmt.Println("DLL ready at:", dllPath)

	dev, err = tun.CreateTUN("LeapTun", 1500)
	if err != nil {
		log.Fatal(err)
	}
	tunStarted = true

	devName, _ = dev.Name()
	mtu, _ := dev.MTU()
	log.Printf("[INFO] TUN 已创建: %s (MTU=%d)", devName, mtu)

	// 批量缓冲
	batch := dev.BatchSize()
	if batch <= 0 {
		batch = 8
	}
	bufs := make([][]byte, batch)
	sizes := make([]int, batch)
	for i := range bufs {
		bufs[i] = make([]byte, 1500)
	}

	wg = sync.WaitGroup{}
	stop = make(chan struct{})
	stopOnce = sync.Once{}
	wsOnce = sync.Once{}
	wsWriteQueue = make(chan msg, 1024)

	type packet struct {
		dstIP string
		data  []byte
	}

	sendQueue := make(chan packet, 1<<14)

	c = NewConvertor(WriteBytesToTun)

	c.StartTCPForwarder(func(tunConn net.Conn, id *stack.TransportEndpointID) {
		if debug {
			log.Println("拿到连接了！！！")
			log.Println(id.LocalAddress)
			log.Println("cmServer count: ", len(cmServer.Keys()))
		}
		tunConnHandler := NewConnHandler(tunConn, 1<<14, 0, 0, func(cw *ConnHandler, n int, err error) {
			if err != nil {
				wg.Add(1)
				go func() {
					defer wg.Done()
					if debug {
						log.Println("数据写入失败")
					}
					cmServer.Delete(*id)
					_ = cw.Close()
					serverData := make([]byte, 17)
					serverData[0] = 4
					copy(serverData[1:5], id.LocalAddress.AsSlice())
					copy(serverData[5:9], id.LocalAddress.AsSlice())
					copy(serverData[9:13], id.RemoteAddress.AsSlice())
					binary.BigEndian.PutUint16(serverData[13:15], id.LocalPort)
					binary.BigEndian.PutUint16(serverData[15:17], id.RemotePort)
					writeMessageAsync(wsConn, websocket.BinaryMessage, serverData)
				}()
			}
		})
		cmServer.Set(*id, tunConnHandler)
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, 1<<14)
			errStop := false
			for {
				select {
				case <-stop:
					cmServer.Delete(*id)
					_ = tunConnHandler.Close()
					log.Println("[INFO] TCP Forwarder goroutine 退出")
					closeAll(wsConn)
					return
				default:
				}
				if errStop {
					serverData := make([]byte, 17)
					serverData[0] = 4
					copy(serverData[1:5], id.LocalAddress.AsSlice())
					copy(serverData[5:9], id.LocalAddress.AsSlice())
					copy(serverData[9:13], id.RemoteAddress.AsSlice())
					binary.BigEndian.PutUint16(serverData[13:15], id.LocalPort)
					binary.BigEndian.PutUint16(serverData[15:17], id.RemotePort)
					writeMessageAsync(wsConn, websocket.BinaryMessage, serverData)
					return
				}
				n, err := tunConnHandler.conn.Read(buf)
				if err != nil {
					if debug {
						log.Println("Read error:", err)
					}
					cmServer.Delete(*id)
					_ = tunConnHandler.Close()
					errStop = true
				}

				data := buf[:n]

				serverData := make([]byte, 17+len(data))

				serverData[0] = 2
				copy(serverData[1:5], id.LocalAddress.AsSlice())
				copy(serverData[5:9], id.LocalAddress.AsSlice())
				copy(serverData[9:13], id.RemoteAddress.AsSlice())
				binary.BigEndian.PutUint16(serverData[13:15], id.LocalPort)
				binary.BigEndian.PutUint16(serverData[15:17], id.RemotePort)
				copy(serverData[17:], data)

				writeMessageAsync(wsConn, websocket.BinaryMessage, serverData)
			}
		}()
	})

	// 上行 goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				log.Println("[INFO] 上行 goroutine 退出")
				closeAll(wsConn)
				return
			default:
			}
			n, err := dev.Read(bufs, sizes, tunPacketOffset)
			if err != nil {
				select {
				case <-stop:
					log.Println("[INFO] 上行 goroutine 退出")
					return
				default:
				}
				log.Println("[ERROR] TUN Read 出错:", err)
				time.Sleep(100 * time.Millisecond)
				continue
			}
			for i := 0; i < n; i++ {
				data := bufs[i][tunPacketOffset : tunPacketOffset+sizes[i]]
				dstIP := getDstIP(data)
				if dstIP == "" || ip == "" || !isSameSubnet(dstIP, ip) || ip == dstIP {
					continue
				}
				if len(data) <= 9 {
					continue
				}
				if data[9] == 6 {
					c.SendBytes(data)
					continue
				}
				if data[9] != 17 && data[9] != 1 && data[9] != 2 {
					continue
				}
				p := packet{dstIP: dstIP, data: append([]byte(nil), data...)}
				select {
				case sendQueue <- p:
				default:
					<-sendQueue
					sendQueue <- p
				}
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		batchSizeBytes := 64 * 1024
		flushInterval := 5 * time.Millisecond

		var curIP string
		var buf []byte
		timer := time.NewTimer(flushInterval)
		defer timer.Stop()

		flush := func() {
			if len(buf) > 0 && curIP != "" {
				ipBytes := net.ParseIP(curIP).To4()
				if ipBytes == nil {
					buf = buf[:0]
					curIP = ""
					return
				}

				// 整帧格式: [1][dstIP(4)][buf...]
				out := make([]byte, 5+len(buf))
				out[0] = 1
				copy(out[1:5], ipBytes)
				copy(out[5:], buf)

				writeMessageAsync(wsConn, websocket.BinaryMessage, out)
				buf = buf[:0]
				curIP = ""
			}
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(flushInterval)
		}

		for {
			select {
			case <-stop:
				flush()
				log.Println("[INFO] 发送 goroutine 退出")
				closeAll(wsConn)
				return
			case p, ok := <-sendQueue:
				if !ok {
					flush()
					log.Println("[INFO] 发送队列已关闭，退出发送 goroutine")
					return
				}
				// 如果当前 IP 为空，初始化
				if curIP == "" {
					curIP = p.dstIP
				}
				// 如果 IP 不同，先 flush 再开启新批次
				if curIP != p.dstIP {
					flush()
					curIP = p.dstIP
				}
				// 写入 [len|payload]
				if len(buf)+2+len(p.data) > batchSizeBytes {
					flush()
					curIP = p.dstIP
				}
				tmp := make([]byte, 2+len(p.data))
				binary.BigEndian.PutUint16(tmp[0:2], uint16(len(p.data)))
				copy(tmp[2:], p.data)
				buf = append(buf, tmp...)
			case <-timer.C:
				flush()
			}
		}
	}()

	// 下行循环（改为二进制格式）
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				log.Println("[INFO] 下行 goroutine 退出")
				closeAll(wsConn)
				return
			default:
			}

			_, message, err := wsConn.ReadMessage()
			if err != nil {
				select {
				case <-stop:
					log.Println("[INFO] 下行 goroutine 退出")
					closeAll(wsConn)
					return
				default:
				}
				log.Println("[ERROR] 读取消息失败:", err)
				stopOnce.Do(func() { close(stop) })
				continue
			}

			if len(message) < 1 {
				continue
			}

			msgType := message[0]
			data := message[1:]

			if msgType == 0 {
				// JSON 消息
				var msg Message
				if err := json.Unmarshal(data, &msg); err != nil {
					log.Println("[ERROR] 解析 JSON 失败:", err)
					continue
				}

				switch msg.Type {
				case "updateStatus":
					var status struct {
						Username           string `json:"username"`
						RoomName           string `json:"roomName"`
						IP                 string `json:"ip"`
						RemainingBandwidth string `json:"remainingBandwidth"`
						RoomMembers        []struct {
							Name   string `json:"name"`
							IP     string `json:"ip"`
							Online bool   `json:"online"`
						} `json:"roomMembers"`
					}
					if err := json.Unmarshal(msg.Data, &status); err != nil {
						log.Println("[ERROR] 解析 updateStatus 失败:", err)
						continue
					}

					if !debug {
						screen.Clear()
						screen.MoveTopLeft()
					}
					fmt.Println("用户名:", status.Username)
					fmt.Println("房间名:", status.RoomName)
					fmt.Println("当前 IP:", status.IP)
					fmt.Println("房间剩余带宽:", status.RemainingBandwidth)
					fmt.Println("成员列表:")
					for _, m := range status.RoomMembers {
						if m.Online {
							fmt.Printf(" - %s %s (%s)\n", m.Name, m.IP, "在线")
						} else {
							fmt.Printf(" - %s %s (%s)\n", m.Name, m.IP, "离线")
						}
					}

					if ip != status.IP {
						if err := setIPv4Addr(status.IP); err != nil {
							log.Println("[ERROR] 设置IP失败:", err)
						}
					}
				}
			} else if msgType == 1 {
				if len(data) < 4 {
					continue
				}
				//dstIP := net.IP(data[0:4]).String()
				buf := data[4:]

				for len(buf) >= 2 {
					plen := int(binary.BigEndian.Uint16(buf[0:2]))
					if plen < 0 || len(buf) < 2+plen {
						log.Println("[WARN] 下行包长度异常，丢弃剩余数据")
						break
					}
					payload := buf[2 : 2+plen]

					if _, err := WriteBytesWithLenToTun(payload, plen); err != nil {
						log.Println("[ERROR] 写入 TUN 失败:", err)
					} else if debug {
						log.Printf("[DEBUG] 写入 TUN, len=%d", plen)
					}

					buf = buf[2+plen:]
				}
			} else if msgType == 2 {
				if debug {
					log.Println("收到TCP数据")
				}
				data = data[4:]
				id := decodeEndpointID(data)
				localConnHandler, ok := cmClient.Get(*id)
				if ok {
					if debug {
						log.Println("存在conn继续write")
					}
					localConnHandler.Write(data[12:])
					continue
				} else {
					if debug {
						log.Println("dial: " + ip + ":" + fmt.Sprintf("%d", id.LocalPort))
					}
					localConn, err := net.Dial("tcp", ip+":"+fmt.Sprintf("%d", id.LocalPort))
					if err != nil {
						log.Println("dial err:", err)
						continue
					}
					_, err = localConn.Write(data[12:])
					if err != nil {
						log.Println("write err:", err)
						_ = localConn.Close()
						continue
					}
					localConnHandler = NewConnHandler(localConn, 1024, 0, maxLimit, func(cw *ConnHandler, n int, err error) {
						if err != nil {
							wg.Add(1)
							go func() {
								defer wg.Done()
								cmClient.Delete(*id)
								_ = cw.Close()
								serverData := make([]byte, 17)
								serverData[0] = 4
								copy(serverData[1:5], id.RemoteAddress.AsSlice())
								copy(serverData[5:9], id.LocalAddress.AsSlice())
								copy(serverData[9:13], id.RemoteAddress.AsSlice())
								binary.BigEndian.PutUint16(serverData[13:15], id.LocalPort)
								binary.BigEndian.PutUint16(serverData[15:17], id.RemotePort)
								writeMessageAsync(wsConn, websocket.BinaryMessage, serverData)
							}()
						}
					})
					cmClient.Set(*id, localConnHandler)
					wg.Add(1)
					go func() {
						defer wg.Done()
						buf := make([]byte, 1<<14)
						errStop := false
						for {
							select {
							case <-stop:
								cmClient.Delete(*id)
								_ = localConnHandler.Close()
								log.Println("[INFO] Local TCP Forwarder goroutine 退出")
								closeAll(wsConn)
								return
							default:
							}
							if errStop {
								serverData := make([]byte, 17)
								serverData[0] = 4
								copy(serverData[1:5], id.RemoteAddress.AsSlice())
								copy(serverData[5:9], id.LocalAddress.AsSlice())
								copy(serverData[9:13], id.RemoteAddress.AsSlice())
								binary.BigEndian.PutUint16(serverData[13:15], id.LocalPort)
								binary.BigEndian.PutUint16(serverData[15:17], id.RemotePort)
								writeMessageAsync(wsConn, websocket.BinaryMessage, serverData)
								return
							}
							n, err := localConnHandler.Read(buf)
							if err != nil {
								if debug {
									log.Println("Dial Read error:", err)
								}
								cmClient.Delete(*id)
								_ = localConnHandler.Close()
								errStop = true
							}

							data := buf[:n]
							if debug {
								//log.Println("dial read:", len(data))
							}

							serverData := make([]byte, 17+len(data))

							serverData[0] = 3
							copy(serverData[1:5], id.RemoteAddress.AsSlice())
							copy(serverData[5:9], id.LocalAddress.AsSlice())
							copy(serverData[9:13], id.RemoteAddress.AsSlice())
							binary.BigEndian.PutUint16(serverData[13:15], id.LocalPort)
							binary.BigEndian.PutUint16(serverData[15:17], id.RemotePort)
							copy(serverData[17:], data)
							writeMessageAsync(wsConn, websocket.BinaryMessage, serverData)
						}
					}()
				}
			} else if msgType == 3 {
				if debug {
					//log.Println("收到TCP数据返回")
				}
				data = data[4:]
				id := decodeEndpointID(data)
				tunConnHandler, ok := cmServer.Get(*id)
				if ok {
					if debug {
						//log.Println("收到TCP数据返回，数据写入")
					}
					tunConnHandler.Write(data[12:])
				}
			} else if msgType == 4 {
				if debug {
					log.Println("收到关闭连接")
				}
				data = data[4:]
				id := decodeEndpointID(data)
				connClient, ok := cmClient.Get(*id)
				if ok {
					if debug {
						log.Println("收到关闭连接，开始关闭")
					}
					cmClient.Delete(*id)
					wg.Add(1)
					go func() {
						defer wg.Done()
						err := connClient.Close()
						if err != nil && debug {
							log.Println("关闭连接失败：", err)
						}
					}()
				}
				connServer, ok := cmServer.Get(*id)
				if ok {
					if debug {
						log.Println("收到关闭连接，开始关闭")
					}
					cmServer.Delete(*id)
					wg.Add(1)
					go func() {
						defer wg.Done()
						err := connServer.Close()
						if err != nil && debug {
							log.Println("关闭连接失败：", err)
						}
					}()
				}
			} else if msgType == 5 {
				if debug {
					log.Println("收到来自服务器自发的关闭连接")
				}
				ip := tcpip.AddrFrom4Slice(data[0:4])
				for _, id := range cmServer.Keys() {
					if id.LocalAddress == ip {
						conn, ok := cmServer.Get(id)
						if ok {
							if debug {
								log.Println("收到关闭连接，开始关闭")
							}
							cmServer.Delete(id)
							wg.Add(1)
							go func() {
								defer wg.Done()
								err := conn.Close()
								if err != nil && debug {
									log.Println("关闭连接失败：", err)
								}
							}()
						}
					}
				}
				for _, id := range cmClient.Keys() {
					if id.RemoteAddress == ip {
						conn, ok := cmClient.Get(id)
						if ok {
							if debug {
								log.Println("收到关闭连接，开始关闭")
							}
							cmClient.Delete(id)
							wg.Add(1)
							go func() {
								defer wg.Done()
								err := conn.Close()
								if err != nil && debug {
									log.Println("关闭连接失败：", err)
								}
							}()
						}
					}
				}
			}
		}
	}()

	// 等待 goroutine 退出
	wg.Wait()
	ip = ""
	tunStarted = false
	closeAll(wsConn)
	close(sendQueue)
	log.Println("[INFO] run() 已退出")
}

type msg struct {
	typ  int
	data []byte
}

var (
	wsWriteQueue chan msg
	wsOnce       sync.Once
)

func initWsWriter(wsConn *websocket.Conn) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				log.Println("[INFO] 异步发送 goroutine 退出")
				closeAll(wsConn)
				return
			case m := <-wsWriteQueue:
				_ = wsConn.SetWriteDeadline(time.Now().Add(10 * time.Second))
				if err := wsConn.WriteMessage(m.typ, m.data); err != nil {
					select {
					case <-stop:
						log.Println("[INFO] 异步发送 goroutine 退出")
						closeAll(wsConn)
						return
					default:
					}
					log.Println("[ERROR] 发送失败:", err)
					stopOnce.Do(func() { close(stop) })
				}
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		currentLimit := maxLimit
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				queueUsage := float64(len(wsWriteQueue)) / float64(cap(wsWriteQueue))

				needToSet := false
				// 调整策略
				if queueUsage > 0.8 {
					currentLimit -= 1 << 18 //256KB/s
					if currentLimit < 1 {
						currentLimit = 1
					}
					needToSet = true
				} else if queueUsage < 0.01 && currentLimit != maxLimit {
					currentLimit += 1 << 16 //64KB/s
					if currentLimit > maxLimit {
						currentLimit = maxLimit
					}
					needToSet = true
				}

				if needToSet {
					for _, id := range cmClient.Keys() {
						conn, ok := cmClient.Get(id)
						if !ok {
							continue
						}
						conn.SetReadLimit(currentLimit)
						if debug {
							log.Printf("[Limiter] set client limit=%d", currentLimit)
						}
					}
					for _, id := range cmServer.Keys() {
						conn, ok := cmServer.Get(id)
						if !ok {
							continue
						}
						conn.SetReadLimit(currentLimit)
					}
				}
				if debug {
					log.Printf("[Limiter] queueUsage=%.2f, newLimit=%d", queueUsage, currentLimit)
				}
			}
		}
	}()
}

func writeMessageAsync(wsConn *websocket.Conn, messageType int, data []byte) {
	closeLocker.Lock()
	defer closeLocker.Unlock()
	wsOnce.Do(func() { initWsWriter(wsConn) })
	if !allClosed {
		wsWriteQueue <- msg{typ: messageType, data: data}
	}
}

func WriteBytesToTun(payload []byte) (int, error) {
	out := make([]byte, tunPacketOffset+len(payload))
	copy(out[tunPacketOffset:], payload)
	return dev.Write([][]byte{out}, tunPacketOffset)
}

func WriteBytesWithLenToTun(payload []byte, plen int) (int, error) {
	out := make([]byte, tunPacketOffset+plen)
	copy(out[tunPacketOffset:], payload)
	return dev.Write([][]byte{out}, tunPacketOffset)
}
