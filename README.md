# Eyeworm V 1.2.0 
一款强大的内网信息收集工具，支持文件、文件夹、文件内容、命令、注册表、进程、mimikatz命令、dpapi、最近访问收集，且支持定制化配置，只需更新配置文件，定义收集规则，即可开启对各类浏览器、remote工具、聊天软件进行凭据、信息收集
## 功能
-wfiles  根据配置文件对文件、文件夹、内容收集 文件名支持通配符 *，?  例如: a?c、ab* 、 *密码


-wcommands  根据配置文件的cmd命令集收集输出信息（結合wfiles，可进行命令结果文件收集）


-wprocess 根据配置文件的进程名，匹配正在运行的进程路径进行信息收集


-wregistry 根据配置文件配置收集注册表项信息


-wrecent  根据配置文件配置收集最近访问中的目标文件


-wmimikatz 根据配置文件配置 使用加密型mimikatz进行结果收集


-dpapi 获得Masterkey


-spy 开启监控，关机后结束


-redeye 开启常驻模式（开机自启），需要配置 回传邮件、打包密码、常驻规则。（该模式已经实现免杀和隐藏，必须用相同配置文件的unred解除）
例如 ：`Eyeworm -wfiles -wcommands -redEye` 开启文件、命令 的常驻收集


-upload 上传收集结果 需要配置 回传邮件、打包密码


-o="result.txt" 把收集结果输出文件


-keylog 键盘记录功能开启（必须开启redeye或spy）


-unred 解除该电脑的redeye常驻模式

##配置文件 EyeConfig.json
下列是单个收集策略：
`        {

            "RuleName":"DefultFilesWorm",         //规则名称 如扩展chromeWorm，QQBrowerWorm 用于区分
            
            "OS": "Windows",                      //操作系统   
            
            "CollectorType": "File",              //收集策略类型， 如wfiles 收集的就是类型为File的收集策略 （File 文件收集，Command 命令收集，Recent 最近访问，Process 进程收集，Registry 注册表收集 APi mimikatz收集）
            
            "Category": "defult",
            
            "Locations":[ "C:/Users/V/Desktop/vvvsss/sss"],
            
            "ContentKeys": ["\"_id\":"],
            
            "FileName":["*"],
            
            "SuffixTypes":[".txt"],
            
            "Explain": "文件及文件夹收集,支持 * 通配符  ",
            
            "Commands":null,
            
            "ProcessName": null,
            
            "DeCrypt": false,
            
            "DeCryptCommand": null
            
        },`
