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
const IPProtoTCP = 6

var (
	tunStarted = false
	ip         = "10.0.0.0"
	stop       = make(chan struct{})
	stopOnce   sync.Once
	devName    string
	dev        tun.Device
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
	mu    sync.Mutex
	conns map[stack.TransportEndpointID]net.Conn
}

func (cm *ConnMap) Set(id stack.TransportEndpointID, conn net.Conn) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.conns[id] = conn
}

func (cm *ConnMap) Get(id stack.TransportEndpointID) (net.Conn, bool) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	c, ok := cm.conns[id]
	return c, ok
}

func (cm *ConnMap) Delete(id stack.TransportEndpointID) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	delete(cm.conns, id)
}

func (cm *ConnMap) Keys() []stack.TransportEndpointID {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	keys := make([]stack.TransportEndpointID, 0, len(cm.conns))
	for k := range cm.conns {
		keys = append(keys, k)
	}
	return keys
}

var cmServer = &ConnMap{
	conns: make(map[stack.TransportEndpointID]net.Conn),
}

var cmClient = &ConnMap{
	conns: make(map[stack.TransportEndpointID]net.Conn),
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
var closeLocker = sync.Mutex{}

func closeAll(conn *websocket.Conn) {
	closeLocker.Lock()
	defer closeLocker.Unlock()
	if allClosed {
		return
	}
	allClosed = true
	dev.Close()
	conn.Close()
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

	var wg sync.WaitGroup
	stop = make(chan struct{})
	stopOnce = sync.Once{}

	type packet struct {
		dstIP string
		data  []byte
	}

	sendQueue := make(chan packet, 1024)

	c := NewConvertor(WriteBytes)

	c.StartTCPForwarder(func(newConn net.Conn, id *stack.TransportEndpointID) {
		if debug {
			log.Println("拿到连接了！！！")
			log.Println(id.LocalAddress)
		}
		cmServer.Set(*id, newConn)
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, 1<<14)
			errStop := false
			for {
				select {
				case <-stop:
					cmServer.Delete(*id)
					newConn.Close()
					log.Println("[INFO] TCP Forwarder goroutine 退出")
					c.Close()
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
					if err := SafeWriteMessage(wsConn, websocket.BinaryMessage, serverData); err != nil {
						log.Println("[ERROR] 发送失败:", err)
						stopOnce.Do(func() { close(stop) })
					}
					return
				}
				n, err := newConn.Read(buf)
				if err != nil {
					if debug {
						log.Println("Read error:", err)
					}
					cmServer.Delete(*id)
					newConn.Close()
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

				if err := SafeWriteMessage(wsConn, websocket.BinaryMessage, serverData); err != nil {
					log.Println("[ERROR] 发送失败:", err)
					stopOnce.Do(func() { close(stop) })
				}
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
				c.Close()
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
				if ip == "" || !isSameSubnet(dstIP, ip) || ip == dstIP {
					continue
				}
				// 放入队列（payload + IP）
				//log.Println(len(data))
				//a, _ := isPureAck(data)
				//log.Println(a)
				//if a {
				//continue
				//}
				//a, _ = needAck(data)
				//log.Println(a)
				//if a {
				/*fakeAck, _ := makeAckPacket(data)
				go func() {
					time.Sleep(40*time.Millisecond)
					out := make([]byte, tunPacketOffset+len(fakeAck))
					copy(out[tunPacketOffset:], fakeAck)

					if _, err := dev.Write([][]byte{out}, tunPacketOffset); err != nil {
						log.Println("[ERROR] 写入 TUN 失败:", err)
					} else if debug {
						log.Printf("[DEBUG] 写入 Fake ACK, len=%d, dst=%s", len(fakeAck), dstIP)
					}
				}()*/
				//}

				if len(data) > 9 && data[9] == IPProtoTCP {
					c.SendBytes(data)
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
				out := make([]byte, 1+4+len(buf))
				out[0] = 1
				copy(out[1:5], ipBytes)
				copy(out[5:], buf)

				if err := SafeWriteMessage(wsConn, websocket.BinaryMessage, out); err != nil {
					log.Println("[ERROR] 批量发送失败:", err)
					stopOnce.Do(func() { close(stop) })
				}
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
				c.Close()
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
				c.Close()
				closeAll(wsConn)
				return
			default:
			}

			_, message, err := wsConn.ReadMessage()
			if err != nil {
				select {
				case <-stop:
					log.Println("[INFO] 下行 goroutine 退出")
					c.Close()
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

					screen.Clear()
					screen.MoveTopLeft()
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

					WriteBytesWithLen(payload, plen)

					buf = buf[2+plen:]
				}
			} else if msgType == 2 {
				if debug {
					log.Println("收到TCP数据")
				}
				data = data[4:]
				id := decodeEndpointID(data)
				localConn, ok := cmClient.Get(*id)
				if ok {
					if debug {
						log.Println("存在conn继续write")
					}
					_, err := localConn.Write(data[12:])
					if err != nil {
						cmClient.Delete(*id)
						continue
					}
				} else {
					if debug {
						log.Println("dial: " + ip + ":" + fmt.Sprintf("%d", id.LocalPort))
					}
					localConn, err = net.Dial("tcp", ip+":"+fmt.Sprintf("%d", id.LocalPort))
					if err != nil {
						log.Println("dial err:", err)
						continue
					}
					_, err := localConn.Write(data[12:])
					if err != nil {
						log.Println("write err:", err)
						continue
					}
					cmClient.Set(*id, localConn)
					wg.Add(1)
					go func() {
						defer wg.Done()
						buf := make([]byte, 1<<14)
						errStop := false
						for {
							select {
							case <-stop:
								cmClient.Delete(*id)
								localConn.Close()
								log.Println("[INFO] TCP Forwarder goroutine 退出")
								c.Close()
								closeAll(wsConn)
								return
							default:
							}
							if errStop {
								serverData := make([]byte, 17+len(data))
								serverData[0] = 4
								copy(serverData[1:5], id.RemoteAddress.AsSlice())
								copy(serverData[5:9], id.LocalAddress.AsSlice())
								copy(serverData[9:13], id.RemoteAddress.AsSlice())
								binary.BigEndian.PutUint16(serverData[13:15], id.LocalPort)
								binary.BigEndian.PutUint16(serverData[15:17], id.RemotePort)
								if err := SafeWriteMessage(wsConn, websocket.BinaryMessage, serverData); err != nil {
									log.Println("[ERROR] 发送失败:", err)
									stopOnce.Do(func() { close(stop) })
								}
								return
							}
							n, err := localConn.Read(buf)
							if err != nil {
								if debug {
									log.Println("Dial Read error:", err)
								}
								cmClient.Delete(*id)
								localConn.Close()
								errStop = true
							}

							data := buf[:n]
							if debug {
								log.Println("dial read:", len(data))
							}

							serverData := make([]byte, 17+len(data))

							serverData[0] = 3
							copy(serverData[1:5], id.RemoteAddress.AsSlice())
							copy(serverData[5:9], id.LocalAddress.AsSlice())
							copy(serverData[9:13], id.RemoteAddress.AsSlice())
							binary.BigEndian.PutUint16(serverData[13:15], id.LocalPort)
							binary.BigEndian.PutUint16(serverData[15:17], id.RemotePort)
							copy(serverData[17:], data)

							if err := SafeWriteMessage(wsConn, websocket.BinaryMessage, serverData); err != nil {
								log.Println("[ERROR] 发送失败:", err)
								stopOnce.Do(func() { close(stop) })
							}
						}
					}()
				}
			} else if msgType == 3 {
				if debug {
					log.Println("收到TCP数据返回")
				}
				data = data[4:]
				id := decodeEndpointID(data)
				tunConn, ok := cmServer.Get(*id)
				if ok {
					if debug {
						log.Println("收到TCP数据返回，数据写入")
					}
					wg.Add(1)
					go func() {
						defer wg.Done()
						_, err := tunConn.Write(data[12:])
						if err != nil {
							if debug {
								log.Println("数据写入失败")
							}
							serverData := make([]byte, 17+len(data))
							serverData[0] = 4
							copy(serverData[1:5], id.LocalAddress.AsSlice())
							copy(serverData[5:9], id.LocalAddress.AsSlice())
							copy(serverData[9:13], id.RemoteAddress.AsSlice())
							binary.BigEndian.PutUint16(serverData[13:15], id.LocalPort)
							binary.BigEndian.PutUint16(serverData[15:17], id.RemotePort)
							if err := SafeWriteMessage(wsConn, websocket.BinaryMessage, serverData); err != nil {
								log.Println("[ERROR] 发送失败:", err)
								stopOnce.Do(func() { close(stop) })
							}
						}
					}()
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
	c.Close()
	closeAll(wsConn)
	close(sendQueue)
	log.Println("[INFO] run() 已退出")
}

var wsMu sync.Mutex

func SafeWriteMessage(conn *websocket.Conn, msgType int, data []byte) error {
	wsMu.Lock()
	defer wsMu.Unlock()
	return conn.WriteMessage(msgType, data)
}

func WriteBytes(payload []byte) (int, error) {
	plen := len(payload)
	out := make([]byte, tunPacketOffset+plen)
	copy(out[tunPacketOffset:], payload)

	return dev.Write([][]byte{out}, tunPacketOffset)
}

func WriteBytesWithLen(payload []byte, plen int) {
	out := make([]byte, tunPacketOffset+plen)
	copy(out[tunPacketOffset:], payload)

	if _, err := dev.Write([][]byte{out}, tunPacketOffset); err != nil {
		log.Println("[ERROR] 写入 TUN 失败:", err)
	} else if debug {
		log.Printf("[DEBUG] 写入 TUN, len=%d", plen)
	}
}
