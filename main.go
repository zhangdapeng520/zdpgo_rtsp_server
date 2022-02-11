package main

import (
	"os"

	"github.com/zhangdapeng520/zdpgo_rtsp_server/internal/core"
)

func main() {
	// 创建服务
	s, ok := core.New(os.Args[1:])

	// 异常退出
	if !ok {
		os.Exit(1)
	}

	// 等待退出
	s.Wait()
}
