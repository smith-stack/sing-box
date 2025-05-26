## **更新内容**
- **V 1.12.0 Prerelease-alpha适配sing-box1.12.0版本。**
- **添加对AnyTLS协议的支持。**
- **sing-box服务端及客户端配置更新。**
- **Clash客户端DNS防泄漏配置。**
- **V 1.12.0 Prerelease-alpha为测试版，稳定版请使用V 1.5.0。**


## **说明**
- **脚本使用sing-box、Juicity内核。**
- **脚本支持 CentOS 8+、Debian 10+、Ubuntu 20+ 操作系统。**
- **脚本所有协议均支持自签证书（NaiveProxy除外）。**
- **脚本支持多用户。**
- **脚本支持所有协议共存。**
- **脚本支持自签100年证书。**
- **脚本支持HTTP、WebSocket、gRPC、HTTPUpgrade传输协议。**
- **脚本支持 Multiplex、TCP Brutal、ECH 配置；若要启用 Multiplex、TCP Brutal，sing-box 内核需 ≥1.7.0，请在服务端自行安装 TCP Brutal。**
- **脚本支持自定义各种配置参数；如果不懂如何配置，直接回车即可，脚本会自动随机生成配置（包括用户名、UUID、用户密码等）。**

## **安装**
### **Debian&&Ubuntu使用以下命令安装依赖**
```
apt update && apt -y install curl wget tar socat jq git openssl uuid-runtime build-essential zlib1g-dev libssl-dev libevent-dev dnsutils xxd net-tools cron
```
### **CentOS使用以下命令安装依赖**
```
yum update && yum -y install curl wget tar socat jq git openssl util-linux gcc-c++ zlib-devel openssl-devel libevent-devel bind-utils xxd net-tools cronie
```
### **使用以下命令运行脚本**

- **V1.5.0 请使用以下命令运行脚本**
```
wget -N -O /usr/local/bin/singbox.sh https://raw.githubusercontent.com/smith-stack/sing-box/refs/heads/main/Install.sh && chmod +x /usr/local/bin/singbox.sh && ln -sf /usr/local/bin/singbox.sh /usr/local/bin/singbox && bash /usr/local/bin/singbox.sh
```

- **V1.12.0 Prerelease-alpha 请使用以下命令运行脚本**
```
wget -N -O /usr/local/bin/singbox.sh https://raw.githubusercontent.com/smith-stack/sing-box/refs/heads/main/Pre_release_install.sh && chmod +x /usr/local/bin/singbox.sh && ln -sf /usr/local/bin/singbox.sh /usr/local/bin/singbox && bash /usr/local/bin/singbox.sh
```

## **使用方法**
- **如果开启ECH配置则不会生成Clash客户端配置文件。**
- **Clash客户端配置文件位于/usr/local/etc/sing-box/clash.yaml，下载后加载到 Clash 客户端即可使用，需要配合 Meta 内核。**
- **sing-box电脑端配置文件位于/usr/local/etc/sing-box/win_client.json，下载后加载到 V2rayN、SFM 客户端即可使用。**
- **sing-box手机端配置文件位于/usr/local/etc/sing-box/phone_client.json，下载后加载到 SFA、SFI 客户端即可使用。**

## **脚本支持的节点类型**
- **SOCKS**
- **HTTP**
- **AnyTLS**
- **TUIC V5**
- **Juicity**
- **WireGuard**
- **Hysteria2**
- **VLESS+TCP**
- **VLESS+WebSocket**
- **VLESS+gRPC**
- **VLESS+HTTPUpgrade**
- **VLESS+Vision+REALITY**
- **VLESS+H2C+REALITY**
- **VLESS+gRPC+REALITY**
- **Direct**
- **Trojan+TCP**
- **Trojan+WebSocket**
- **Trojan+gRPC**
- **Trojan+HTTPUpgrade**
- **Trojan+TCP+TLS**
- **Trojan+H2C+TLS**
- **Trojan+gRPC+TLS**
- **Trojan+WebSocket+TLS**
- **Trojan+HTTPUpgrade+TLS**
- **Hysteria**
- **ShadowTLS V3**
- **NaiveProxy**
- **Shadowsocks**
- **VMess+TCP**
- **VMess+WebSocket**
- **VMess+gRPC**
- **VMess+HTTPUpgrade**   
- **VMess+TCP+TLS**
- **VMess+WebSocket+TLS** 
- **VMess+H2C+TLS**
- **VMess+gRPC+TLS** 
- **VMess+HTTPUpgrade+TLS** 

## **免责声明**
- **本项目旨在维护 TinrLin 的脚本。**
- **本项目仅供学习与交流，请于下载后 24 小时内删除，禁止用于商业或非法目的。**
- **使用本脚本必循遵守部署服务器所在地、所在国家和用户所在国家的法律法规，脚本作者及维护者不对使用者的任何不当行为负责。**
