

# 主要目录说明

### Docker相关部分

docker-compose.yaml Docker容器运行，占用端口8000
http 是Docker的HTTP服务部分
SecretDetection 是SD扫描能力源码。
SecretDetectionDir 放已经编译好的程序以及规则

### 过度文件，非部署

**RulesDescriptionMatch** 非正式目录，给任鑫提供接口时的过度文件

**SecretDetectionDriver** 用来批量查看不同熵值扫描的影响


# SD Docker

## 部署

复制 1. docker-compose.yaml 和 2. SecretDetectionDir 到服务器某目录下，随后`docker-compose up -d` 运行即可。

### 组成部分介绍

主要有两部分组成:

* http
* SecretDetection

![](images/mdmd2022-10-10-14-09-06.png)

## 源代码

目录 `http` 使用golang的`net/http`写的http服务，命令行调用SD进行工作，大部分配置可以从`config/local_config.yaml`直接进行配置

目录 `SecretDetection` 是经过优化后的SecretDetection，对其中的线程数、参数等信息进行了更改。

`config/SD.toml`没什么用了其实，程序使用的`SD-all-kill.toml`和`SD-n-all-kill.toml`更多一些。`SD-all-kill.toml`中有非常容易导致误报的规则，用来进行疯狂模式的硬编码匹配；`SD-n-all-kill.toml`较为标准一些，误报率低。

# 接口

![](images/mdmd2022-09-05-17-15-28.png)

# 测试

用几个如图的zip包进行了测试，发现运行良好。只有sca项目用时过长，依然在分析其原因。

多线程处理、sdm的回连URI异常等问题均稳定，不影响主进程的http开启。

![](images/mdmd2022-09-05-17-22-34.png)

# TODO

- [x] 优化toml中的规则命名，使得sdm进行统计时可以区别大类统计与详细统计模式
- [x] 异常处理，如果遇到类似sca.zip的这类文件，扫描时长过于长
- [x] 解决git log 扫描问题：发现程序本身使用git扫描，该问题和任鑫之前遗留了较长时间，单纯是因为没有安装git，已解决。








