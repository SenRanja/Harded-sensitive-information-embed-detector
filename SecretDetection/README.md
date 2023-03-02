
# TODO

- [ ] 优化对于低长度和低复杂度凭证的检出

# 程序简要说明

### 关键算法阈值

##### 升降率和单词识别率

*detect/detect.go*

**标准值**

```
if UpDownRate <= 0.4 || WordsRate >= 0.32
```

##### 香农熵

阈值取决于规则中的`entropy`

##### 高检出模糊匹配

**标准值**

```toml
[[rules]]
description = "高检出模糊匹配--模糊匹配"
id = "generic-high-checkout"
regex = '''(?i)(?:['|\"|:|=]{1,3})((?i)[\w]{8,70})(?:['|\"|\n|\r|\s|\x60]|$)'''
secretGroup = 1
entropy = 4.0
keywords = [
    "password","access_key","access_token","admin_pass","admin_user","algolia_admin_key", ...
]
```

### 打包default.toml

`go-bindata.exe -pkg bindata -o n_all_kill.go passwordtop100.txt KeyboardWalk.txt default.toml american-english`

# 打包

由于写为docker的服务端属于，非打包情况，工具的`-c`是由**http模块**单独控制参数去使用`all-kill`规则。

但是论打包的话，需要单独集成一下`all-kill`规则，因为之前贝总要求修改的原因，http模块



