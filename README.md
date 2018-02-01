# 基于ioctlbf框架编写的驱动漏洞挖掘工具kDriver Fuzzer

作者：k0shl  

作者博客：https://whereisk0shl.top

kDriver Fuzzer整体细节：https://whereisk0shl.top/post/2018-01-30

ioctlbf项目地址：https://github.com/koutto/ioctlbf

kDriver Fuzzer项目地址：https://github.com/k0keoyo/kDriver-Fuzzer

联系我：k0pwn_0110@sina.cn

- - - - --

### kDriver Fuzzer使用说明

- - - - -
首先感谢ioctlbf框架作者，我在这半年的时间阅读调试了很多优秀的fuzzer，受益良多，自己也有了很多想法，正在逐步实现。同时当我调试ioctlbf的时候发现了一些问题，于是基于ioctlbf框架，加了一些自己的想法在里面，有了这个kDriver Fuzzer，利用这个kDriver Fuzzer，我也在2017年收获了不同厂商，不同驱动近100个CVE，其实关于驱动的Fuzz很早就有人做了，我将我这个kDriver Fuzzer开源出来和大家分享共同学习（必要注释已经写在代码里了），同时春节将近，在这里给大家拜年，祝大家新年红包多多，0day多多！（由于并非是自己从头到尾写的项目，其中有部分编码习惯造成的差异（已尽量向框架作者靠拢）请大家见谅，同时代码写的还不够优雅带来的算法复杂度以及代码冗余也请大家海涵，以及一些待解决的问题未来都会逐步优化：））

####一些环境说明：

编译环境：Windows 10 x64 build 1607 

项目IDE：VS2013

测试环境：Windows 7 x86、Windows 10 x86 build 1607

#### 参数介绍：

"-l" ：开启日志记录模式（不会影响主日志记录模块）

"-s" ：驱动枚举模块

"-d" ：打开设备驱动的名称

"-i" ：待Fuzz的ioctl code，默认从0xnnnn0000-0xnnnnffff

"-n" ：在探测阶段采用null pointer模式，该模式下极易fuzz 到空指针引用漏洞，不加则常规探测模式

"-r" ：指定明确的ioctl code范围

"-u" ：只fuzz -i参数给定的ioctl code

"-f" ：在探测阶段采用0x00填充缓冲区

"-q" ：在Fuzz阶段不显示填充input buffer的数据内容

"-e" ：在探测和fuzz阶段打印错误信息（如getlasterror()）

"-h" ：帮助信息

####常用Fuzz命令实例：

##### kDriver Fuzz.exe -s

进行驱动枚举，将CreateFile成功的驱动设备名称，以及部分受限的驱动设备名称打印并写入Enum Driver.txt文件中


##### kDriver Fuzz.exe -d X -i 0xaabb0000 -f -l

对X驱动的ioctl code 0xaabb0000-0xaabbffff范围进行探测及对可用的ioctl code进行fuzz，探测时除了正常探测外增加0x00填充缓冲区探测，开启数据日志记录（如增加-u参数，则只对ioctl code 0xaabb0000探测，若是有效ioctl code则进入fuzz阶段）


##### kDriver Fuzz.exe -d X -r 0xaabb1122-0xaabb3344 -n -l

对X驱动的ioctl code 0xaabb1122-0xaabb3344范围内进行探测，探测时采用null pointer模式，并数据日志记录

![](https://github.com/k0keoyo/kDriver-Fuzzer/blob/master/framework.png)


### Thanks:

https://github.com/bee13oy/AV_Kernel_Vulns/tree/master/Zer0Con2017

https://github.com/koutto/ioctlbf
