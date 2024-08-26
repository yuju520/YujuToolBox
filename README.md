# YujuToolBox
一个Shell脚本工具箱

## 简介
本工具箱集成了一系列有用的系统管理工具和脚本，旨在帮助用户轻松管理和优化Linux服务器。

## 支持列表
仅支持Debian、Ubuntu系统

## 使用方法
### 准备
安装curl
```
apt update -y  && apt install -y curl
```
或者
```
apt update -y  && apt install -y wget
```

或者手动下载本脚本至服务器

### 下载并执行
用curl下载
```
curl -sS -O https://raw.githubusercontent.com/yuju520/YujuToolBox/main/yuju.sh && chmod +x yuju.sh && ./yuju.sh
```
用wget下载
```
wget -q https://raw.githubusercontent.com/yuju520/YujuToolBox/main/yuju.sh && chmod +x yuju.sh && ./yuju.sh
```

## 项目参考
https://github.com/kejilion/sh

https://github.com/jerry048/Tune

https://github.com/ztelliot/taierspeed-cli

https://github.com/xykt/IPQuality
