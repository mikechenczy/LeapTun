package main

import (
	"LeapTun/dll"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/gorilla/websocket"
	"github.com/inancgumus/screen"
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

var (
	tunStarted = false
	ip         = "10.0.0.0"
	stop       = make(chan struct{})
	stopOnce   sync.Once
	devName    string
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

func run(conn *websocket.Conn) {
	dllPath, err := dll.EnsureWintunDLL()
	if err != nil {
		panic(err)
	}
	fmt.Println("DLL ready at:", dllPath)

	dev, err := tun.CreateTUN("LeapTun", 1500)
	if err != nil {
		log.Fatal(err)
	}
	defer dev.Close()
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

	// 上行 goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				log.Println("[INFO] 上行 goroutine 退出")
				return
			default:
			}
			n, err := dev.Read(bufs, sizes, tunPacketOffset)
			if err != nil {
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

				if err := conn.WriteMessage(websocket.BinaryMessage, out); err != nil {
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
				return
			default:
			}

			_, message, err := conn.ReadMessage()
			if err != nil {
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
			} else {
				if len(data) < 4 {
					continue
				}
				dstIP := net.IP(data[0:4]).String()
				buf := data[4:]

				for len(buf) >= 2 {
					plen := int(binary.BigEndian.Uint16(buf[0:2]))
					if plen < 0 || len(buf) < 2+plen {
						log.Println("[WARN] 下行包长度异常，丢弃剩余数据")
						break
					}
					payload := buf[2 : 2+plen]

					out := make([]byte, tunPacketOffset+plen)
					copy(out[tunPacketOffset:], payload)

					if _, err := dev.Write([][]byte{out}, tunPacketOffset); err != nil {
						log.Println("[ERROR] 写入 TUN 失败:", err)
					} else if debug {
						log.Printf("[DEBUG] 写入 TUN, len=%d, dst=%s", plen, dstIP)
					}

					buf = buf[2+plen:]
				}
			}
		}
	}()

	// 等待 goroutine 退出
	wg.Wait()
	ip = ""
	tunStarted = false
	close(sendQueue)
	log.Println("[INFO] run() 已退出")
}
