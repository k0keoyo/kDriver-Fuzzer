[Read this in Chinese](README.md)

## A kernel driver fuzzer, based on ioctlbf

A big Thanks to the developers of `ioctlbf`.

In the past few months, I spent a lot of time debugging various high quality fuzzers and I learned a lot from my experience. When I was debugging the `ioctlbf` framework, I found some issues. Meanwhile, I had some great fuzzing ideas in my mind. To implement my ideas and improve the `ioctlbf` framework, I wrote kDriver Fuzzer, based on `ioctlbf`.

Using kDriver Fuzzer, I harvested over 100 CVEs in the drivers written by a variety of software developers, in 2017.

There are many kernel driver fuzzers out there, but kDriver Fuzzer is free open source software, and has a lot of comments in its code, which makes it a good tool for learners. The coding style of this project imitates that of `ioctlbf`.

In addition, Happy Lunar New Year to everyone!

### Development Environments

Compiled on: Windows 10 x64 build 1607

IDE: Visual Studio 2013

Tested on: Windows 7 x86, Windows 10 x86 build 1607

### Usage

| Param | Explanation    |
|-------|----------------|
| `-l`  | Enable logging |
| `-s`  | Driver enumeration mode |
| `-d`  | Driver name |
| `-i`  | Left bound of the ioctl code to fuzz (it's a range: `0xnnnn0000-0xnnnnffff`) |
| `-r`  | Range of ioctl code |
| `-u`  | Only use the ioctl code specified in `-i` |
| `-n`  | Perform "null pointer" fuzzing, instead of regular fuzzing |
| `-f`  | Fill the buffer with `0x00` |
| `-q`  | Do not print input buffer during fuzzing |
| `-e`  | Print error messages (e.g. `getlasterror()`) |
| `-h`  | Help |


```
kDriver Fuzz.exe -s
```

Enumerate drivers, using the `CreateFile` API. Write driver names into `Enum Driver.txt`


```
kDriver Fuzz.exe -d X -i 0xaabb0000 -f -l
```

Fuzz the ioctl code of driver `X`, ranging from `0xaabb0000` to `0xaabbffff`. Fill the buffer with `0x00`. Enable logging.

If you add `-u` here, then only `0xaabb0000` will be fuzzed.


```
kDriver Fuzz.exe -d X -r 0xaabb1122-0xaabb3344 -n -l
```

Perform "null pointer" fuzzing on the ioctl code of driver `X`, ranging from `0xaabb1122` to `0xaabb3344`. Enable logging.

[kDriver Fuzzer diagram (Chinese)](https://github.com/k0keoyo/kDriver-Fuzzer/blob/master/framework.png)


### About the project, and the author

[kDriver Fuzzer](https://github.com/k0keoyo/kDriver-Fuzzer) is developed by [k0shl](https://whereisk0shl.top). You can reach the developer via email: k0pwn_0110@sina.cn

kDriver Fuzzer implementation detail and case studies: https://whereisk0shl.top/post/2018-01-30

### References

Attacking Antivirus Software's Kernel Driver: https://github.com/bee13oy/AV_Kernel_Vulns/tree/master/Zer0Con2017

ioctlbf Repository: https://github.com/koutto/ioctlbf
