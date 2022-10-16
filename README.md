[Click here for English version](https://github.com/imsellbaox/Eyeworm)

# Eyeworm V 1.2.0 介绍

一款Go语言实现的强大的灵活的自定义的信息收集工具，支持文件、文件夹、文件内容、自定义命令、注册表、指定进程、mimikatz命令、dpapi、最近访问记录等内容的收集。支持灵活的定制化配置，只需更新定义收集规则的配置文件，选择需要执行的规则，即可开启对各类浏览器、remote管理工具、敏感关键词、聊天软件进行凭据、信息收集，并且支持持久化，内容加密传输等，持续跟新中，欢迎大家提供更为丰富的收集配置规则集合。



### 我即是虫群!

![EyeWorm](EyeWorm.jpg)

## 特性

- 支持常用软件凭据收集，可配置式的自定义常用软件凭据的文件路径，注册表，后缀等——XML,JSON，INI,TXT格式
- 可通过自定义mremoteNG、MobaXterm、Terminals、Remote Desktop Connection、RDO、XT800、VNC等各种远程控制软件，笔记软件的配置文件，数据 文件，key文件，注册表信息，最近访问记录等等信息的采集。规则集越多，适用环境就越多，采集的信息就越多，欢迎大家在问题区提供自己的配置，我会抽时间整合到主版本里
- 支持Linux,Window下运行（目前只完成了Windows下的实现）
- 支持进程对应路径下凭据收集
- 支持命令执行结果的收集，如运行命令获取环境变量，以及根据关键字提取环境变量里的凭证
- 支持安装脚本临时文件里凭据收集
- 支持文本，文档里的凭据收集（全文检索，已经实现一版，但考虑搜索文件的类型支持，效率和资源占用等问题后续可能需要重构）
- 支持最近访问记录的文件收集
- 支持常见凭据的解密（集成Mimikatz实现）
- 支持keylog
- 支持共享文件，USB存储文件凭据的收集（暂未实现）
- 支持常驻收集时内容相同去重 （暂未实现）
- 支持收集后自动压缩加密传输到外部
- 支持做成cs的插件（暂未实现）

## 命令参数和功能

-all     相当于执行以下 -wfiles -wcommands -wprocess -wregistry -wrecent -wmimikatz -dpapi参数命令
-wfiles  根据配置文件对文件、文件夹、内容收集 文件名支持通配符 *，?  例如: a?c、ab* 、 *密码

-wcommands  根据配置文件的cmd命令集收集输出信息（結合wfiles，可进行命令结果文件收集）

-wprocess 根据配置文件的进程名，匹配正在运行的进程路径进行信息收集

-wregistry 根据配置文件配置收集注册表项信息

-wrecent  根据配置文件配置收集最近访问中的目标文件

-wmimikatz 根据配置文件配置 使用加密型mimikatz进行结果收集

-dpapi 获得Masterkey

-spy 开启监控，关机后结束

-redeye 开启常驻模式（持久化，重启自启），需要配置 回传邮件、打包密码、常驻规则。（该模式已经实现免杀和隐藏，必须用相同配置文件的unred解除）
例如 ：`Eyeworm -wfiles -wcommands -redEye` 开启文件、命令 的常驻收集

-upload 上传收集结果 需要配置 回传邮件、打包密码

-o="result.txt" 把收集结果输出文件

-keylog 键盘记录功能开启（必须开启redeye或spy）

-unred 解除该电脑的redeye常驻模式

## 配置文件 EyeConfig.json说明

通用配置字段在配置文件里都有说明，下面是对单个收集策略字段说明：

`        {

```
        "RuleName":"DefultFilesWorm",         //自定义的规则名称 如扩展chromeWorm，QQBrowerWorm 用于区分
        
        "OS": "Windows",                      //适配操作系统，计划后续版本兼容Linux,Unix   
        
        "CollectorType": "File",              //收集策略对应的类型， 如wfiles 收集的就是类型为File的收集策略，目前主要有以下类别：
                                            （File 文件收集，Command 命令收集，Recent 最近访问，Process 指定进程收集，Registry 注册表收集， APi mimikatz收集）
        
        "Category": "defult",                // 分类 用于规则集合归类如：Browsers、remoteTools,、chatTool
        
        "Locations":["C:/Users/admin/Chrome","E:/QQ"],  //搜索路径集，文件，文件夹必配字段
        
        "ContentKeys": ["\"_id\":","password:"],       //内容收集的匹配关键字，采集内容文件，文件夹市ContentKeys可选字段
        
        "FileName":["*c","a?b","*"],                    //文件名匹配字，文件，文件夹必配字段         
        
        "SuffixTypes":[".txt"],                         // 搜索文件后缀，文件，文件夹必配字段
        
        "Explain": "文件及文件夹收集,支持 * 通配符  ",   //规则作用和配置说明注释字段，=
        
        "Commands":["set && ipconfig/all >>info.txt &&start 'E:\shell.exe'"],    // 命令收集中需要执行的命令，命令收集必配字段）
        
        "ProcessName": ["QQ.exe","Chrome.exe"],                 // 进程收集中的进程，进程收集必配字段。进程采集主要是根据当前系统运行的进程获取其对应的路径，快速定位自定义安装场景下的配置文件或者关键文件的路径
        
        "DeCrypt": false,                                     //   保留字段，本机文件或者数据解密功能（todo）
        
        "DeCryptCommand": null                                //保留字  解密命令 （todo）
        
    },`
```

## 编译和更新配置

### 编译

进入 PackSource 中，配置好ico，EyeConfig.json，versioninfo.json，main.manifest 四个文件 运行PackSource.go 得到 main.syso 在EyeWorm目录下

回到EyeWorm目录下，go build 

### 更新配置文件

考虑AllInOne带来的便利性和安全性，采集配置文件是内嵌exe中的，go编译出来的EXE和节表和其他编译不太一样，防止重复编译麻烦，提供UpdateSource工具更新内嵌的EyeConfig.json 配置文件。考虑到后续Linux的实现，此部分后续很可能需要重构，使用方法:

1. 编译UpdateSource中内容，得到更新工具UpdateSource.exe
2. 根据自己需要修改好EyeConfig.json
3. 编译好`UpdateSource.exe -File=Eyeworm.exe -Data=EyeConfig.json`  即可更新

### 使用

Eyeworm.exe上传在目标机器上执行对应命令
例：`Eyeworm.exe -wfile -wcommand -wprocess -wregistry -wrecent -wmimikatz -keylog -redeye`

![commnd](img1.png)
![config](img2.png)

## ToDo

- 提高内容关键字搜索采集的高效率低资源的采集算法
- 实现Linux/Unix环境下的自定义采集
- 实现Linux/Unix环境下的Keylog
- 实现继承自定义增加一个或者多个，类似mimikatz这样的payload功能
- 实现ELF下的配置文件自更新功能
- 实现自生成对应OS下的采集可执行文件，并每次自动变形加密
- 实现keylog记录文件自定义加密解密
- 支持做成cs的插件
- 实现支持更为隐蔽的自动回传模式，SMTP模式毕竟古老并会泄漏邮箱授权Token

## 注意

需要使用管理員权限运行，否则 常驻和mimikatz功能可能失败

由于集成了mimiktaz，虽然本版本发布的时候做了测试大部分AV都Bypass，但可能由于时间推移导致部分杀软提示有毒，请自行bypass

# 联系我                ---萧枫

本人热爱技术，钻研，欢迎志同道合的兄弟一起研究讨论
邮件：1098516987@qq.com      CSDN:[https://blog.csdn.net/VB551](https://blog.csdn.net/VB551)

# 转载发表请注明原文地址  [https://github.com/imsellbaox/Eyeworm](https://github.com/imsellbaox/Eyeworm)
