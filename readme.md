
# 去工行干活儿

8.18-8.30在工商银行进行了硬编码的服务

8.31要求gitleaks进行docker化

2002.9.5基本完毕

# 过程

## Dockerfile

```
FROM amd64/alpine:3.14

ADD ./GitleaksDir /webscan/

WORKDIR /webscan

EXPOSE 8000

ENTRYPOINT ["/webscan/http"]
```

经过打包之后，生成的image仅23MB左右。


## 程序工作流程

http在接收参数后，赋值file到本地目录，就向客户端发送一个json表示连接正常，然后通过header中的`Connection: close`使得客户端断开连接。

调用子进程扫描完项目后，回连SDM的back_url发送json，然后删除本地的项目的临时目录。


## 源代码

目录 `http` 使用golang的`net/http`写的http服务，命令行调用gitleaks进行工作，大部分配置可以从`config/local_config.yaml`直接进行配置

目录 `gitleaks` 是经过优化后的gitleaks，对其中的线程数、参数等信息进行了更改。

`config/gitleaks.toml`没什么用了其实，程序使用的`gitleaks-all-kill.toml`和`gitleaks-n-all-kill.toml`更多一些。`gitleaks-all-kill.toml`中有非常容易导致误报的规则，用来进行疯狂模式的硬编码匹配；`gitleaks-n-all-kill.toml`较为标准一些，误报率低。

# 接口

![](images/mdmd2022-09-05-17-15-28.png)

# 测试

用几个如图的zip包进行了测试，发现运行良好。只有sca项目用时过长，依然在分析其原因。

多线程处理、sdm的回连URI异常等问题均稳定，不影响主进程的http开启。

![](images/mdmd2022-09-05-17-22-34.png)

# TODO

- [ ] 优化toml中的规则命名，使得sdm进行统计时可以区别大类统计与详细统计模式
- [ ] 异常处理，如果遇到类似sca.zip的这类文件，扫描时长过于长










