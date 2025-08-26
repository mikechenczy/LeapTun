package main

import (
	"LeapTun/dll"
	"encoding/base64"
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

		addrStr := fmt.Sprintf("%s/%s", ip, "24") // 例如 "10.0.0.4/24"
		addr, err := netlink.ParseAddr(addrStr)
		if err != nil {
			return fmt.Errorf("解析地址失败: %v", err)
		}

		if err := netlink.AddrAdd(link, addr); err != nil {
			return fmt.Errorf("添加地址失败: %v", err)
		}

		if err := netlink.LinkSetUp(link); err != nil {
			return fmt.Errorf("启动网卡失败: %v", err)
		}
		return nil
	}
}

func parseIPv4DstPort(pkt []byte) (dstIP string, dstPort int, proto string) {
	if len(pkt) < 20 {
		return "", 0, ""
	}
	if pkt[0]>>4 != 4 {
		return "", 0, ""
	}
	ipDst := net.IP(pkt[16:20]).To4()
	if ipDst == nil {
		return "", 0, ""
	}
	protocol := pkt[9]
	dstIP = ipDst.String()
	switch protocol {
	case 1:
		proto = "icmp"
		dstPort = 0
	case 6:
		if len(pkt) < 24 {
			return dstIP, 0, ""
		}
		dstPort = int(pkt[22])<<8 | int(pkt[23])
		proto = "tcp"
	case 17:
		if len(pkt) < 24 {
			return dstIP, 0, ""
		}
		dstPort = int(pkt[22])<<8 | int(pkt[23])
		proto = "udp"
	default:
		proto = ""
	}
	return
}

func isPrivate24(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	if ip[12] == 10 {
		return true
	}
	if ip[12] == 172 && ip[13] == 16 {
		return true
	}
	if ip[12] == 192 && ip[13] == 168 {
		return true
	}
	return false
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
		bufs[i] = make([]byte, 1<<16)
	}

	var wg sync.WaitGroup
	stop = make(chan struct{})
	stopOnce = sync.Once{}

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
			if n == 0 {
				continue
			}
			for i := 0; i < n; i++ {
				data := bufs[i][tunPacketOffset : tunPacketOffset+sizes[i]]
				dstIP, dstPort, proto := parseIPv4DstPort(data)
				if proto == "" || !isPrivate24(dstIP) || ip == dstIP {
					continue
				}
				pkt := map[string]interface{}{
					"srcIP":    ip,
					"dstIP":    dstIP,
					"protocol": proto,
					"srcPort":  0,
					"dstPort":  dstPort,
					"payload":  base64.StdEncoding.EncodeToString(data),
				}
				message := map[string]interface{}{
					"type": "pkt",
					"data": pkt,
				}
				if err := conn.WriteJSON(message); err != nil {
					log.Println("[ERROR] 发送失败:", err)
					stopOnce.Do(func() { close(stop) })
				} else if debug {
					log.Printf("[DEBUG] %s:%s -> %s:%d, len=%d", pkt["srcIP"], pkt["protocol"], pkt["dstIP"], pkt["dstPort"], len(data))
				}
			}
		}
	}()

	// 下行循环
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
				log.Println("读取消息失败:", err)
				stopOnce.Do(func() { close(stop) })
			}

			var msg Message
			if err := json.Unmarshal(message, &msg); err != nil {
				log.Println("解析 JSON 失败:", err)
				stopOnce.Do(func() { close(stop) })
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
					fmt.Println("解析 updateStatus 失败:", err)
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
					err := setIPv4Addr(status.IP)
					if err != nil {
						fmt.Println("设置IP失败: ", err)
					}
				}
			case "pkt":
				var packet struct {
					SrcIP    string `json:"srcIP"`
					DstIP    string `json:"dstIP"`
					Protocol string `json:"protocol"`
					SrcPort  int    `json:"srcPort"`
					DstPort  int    `json:"dstPort"`
					Payload  []byte `json:"payload"`
				}
				if err := json.Unmarshal(msg.Data, &packet); err != nil {
					fmt.Println("解析 packet 失败:", err)
					continue
				}

				//log.Printf("写入 TUN, len=%d, IP头=%x %x %x %x ...", len(pkt.Payload), pkt.Payload[0], pkt.Payload[1], pkt.Payload[2], pkt.Payload[3])
				buf := make([]byte, tunPacketOffset+len(packet.Payload))
				copy(buf[tunPacketOffset:], packet.Payload)
				_, err := dev.Write([][]byte{buf}, tunPacketOffset)
				if debug {
					if err != nil {
						log.Println("[ERROR] 写入 TUN 失败:", err)
					} else {
						log.Printf("[DEBUG] 写入 TUN, len=%d", len(packet.Payload))
					}
				}
			}
		}
	}()

	// 等待 goroutine 退出
	wg.Wait()
	ip = ""
	tunStarted = false
	log.Println("[INFO] run() 已退出")
}
