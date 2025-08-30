package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
)

const (
	server  = ""
	version = "v1.3"
	website = "https://tun.mjczy.top/"
	source  = "https://github.com/mikechenczy/LeapTun"
	debug   = false
)

var token string

type Message struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data"`
}

func main() {
	reader := bufio.NewReader(os.Stdin)
	fmt.Println("欢迎使用LeapTun")
	fmt.Println("本程序开源无毒，请放心使用，开源地址：", source)
	fmt.Println("客户端版本：", version)
	fmt.Println("管理用户、房间、token，请前往：", website)
	if len(os.Args) == 2 {
		fmt.Print("读取到 token: ")
		token = os.Args[1]
		fmt.Println(token)
	} else {
		fmt.Print("请输入 token: ")
		token, _ = reader.ReadString('\n')
		token = strings.TrimSpace(token)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	stopConn := make(chan struct{})

	go func() {
		for {
			select {
			case <-stopConn:
				log.Println("[INFO] 连接 goroutine 退出")
				return
			default:
			}
			// 构造 JSON 并 Base64 编码
			data := map[string]string{
				"token":   token,
				"version": version,
			}
			jsonBytes, err := json.Marshal(data)
			if err != nil {
				return
			}
			wsURL := fmt.Sprintf(server+"%s", base64.StdEncoding.EncodeToString(jsonBytes))

			parsedURL, err := url.Parse(wsURL)
			if err != nil {
				log.Println("URL Parse err: ", err)
				time.Sleep(5 * time.Second)
				continue
			}
			// 创建 HTTP 客户端（支持重定向）
			client := &http.Client{
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				},
			}

			// 先发送 HTTP 请求，检查是否重定向
			response, err := client.Head("http://" + parsedURL.Host + parsedURL.Path)
			if err == nil {
				// 如果返回 301/302，获取新的 Location
				if response.StatusCode == http.StatusMovedPermanently || response.StatusCode == http.StatusFound {
					newLocation := response.Header.Get("Location")

					// 解析新地址
					newURL, err := url.Parse(newLocation)
					if err != nil {
						log.Println("Parse URL failed: ", err)
						time.Sleep(5 * time.Second)
						continue
					}

					// 修改 ws/wss 前缀
					if newURL.Scheme == "http" {
						newURL.Scheme = "ws"
					} else if newURL.Scheme == "https" {
						newURL.Scheme = "wss"
					}

					// 更新连接地址
					wsURL = newURL.String()
				}
				err = response.Body.Close()
				if err != nil {
					log.Println("[WARN] 连接失败，5秒后重试:", err)
					time.Sleep(5 * time.Second)
					continue
				}
			}

			// 尝试连接
			conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
			if err != nil {
				log.Println("[WARN] 连接失败，5秒后重试:", err)
				time.Sleep(5 * time.Second)
				continue
			}

			fmt.Println("[INFO] 已连接")

			// 读取一次服务器返回的认证消息
			_, message, err := conn.ReadMessage()
			if err != nil {
				log.Println("[WARN] 读取认证消息失败:", err)
				conn.Close()
				time.Sleep(10 * time.Second)
				continue
			}

			var resp map[string]interface{}
			if err := json.Unmarshal(message, &resp); err != nil {
				log.Println("[WARN] 解析认证消息失败:", err)
				conn.Close()
				time.Sleep(10 * time.Second)
				continue
			}

			log.Println(resp["message"])
			if code, ok := resp["code"].(float64); ok && code != 0 {
				log.Println("[ERROR] 5s后程序退出")
				time.Sleep(5 * time.Second)
				os.Exit(0)
			}

			// 调用核心逻辑 run(conn)，断开后自动重连
			run(conn)

			// run 返回说明 WebSocket 已断开
			log.Println("[WARN] WebSocket 断开，5秒后重连...")
			time.Sleep(5 * time.Second)
		}
	}()

	<-sig
	stopOnce.Do(func() { close(stop) })
	close(stopConn)
	time.Sleep(200 * time.Millisecond) // 等 goroutine 优雅退出
	log.Println("[INFO] 客户端退出")
}
