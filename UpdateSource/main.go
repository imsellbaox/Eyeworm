package main

import (
	"flag"
	"fmt"
	"io/ioutil"
)

type FlagStruct struct {
	Help bool
	File string
	Data string
}

var flagStruct = FlagStruct{}

func main() {
	fmt.Println("    ______        __          __              \n   |  ____|       \\ \\        / /                  \n   | |__  _   _  __\\ \\  /\\  / /__  _ __ _ __ ___  \n   |  __|| | | |/ _ \\ \\/  \\/ / _ \\| '__| '_ ` _ \\\n   | |___| |_| |  __/\\  /\\  / (_) | |  | | | | | |\n   |______\\__, |\\___| \\/  \\/ \\___/|_|  |_| |_| |_|\n           __/ |                                  \n          |___/                                   \n  ")
	fmt.Println("欢迎使用 眼虫! UpdateSource 我们将为你服务....         作者：萧枫")
	fmt.Println("使用 -help 查看useage")
	if flagStruct.Data != "" && flagStruct.File != "" {
		content, err := ioutil.ReadFile(flagStruct.Data)
		if err != nil {
			panic(err)
		}
		MyUpdate(flagStruct.File, content, 55, 16)
	}
	if flagStruct.Help {
		flag.Usage()
	}

}

func init() {
	flag.BoolVar(&flagStruct.Help, "help", false, "查看使用方法")
	flag.StringVar(&flagStruct.File, "file", "", "要更新Eyeworm的位置 例如：E:\\Eyeworm.exe ")
	flag.StringVar(&flagStruct.Data, "data", "", "要更新EyeConfig.json的位置 例如：E:\\EyeConfig.json")
	flag.Parse()
}
