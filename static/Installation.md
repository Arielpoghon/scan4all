# Compilation

```sh
sudo apt install -y libpcap-dev golang git
git clone https://github.com/hktalent/scan4all.git
cd scan4all
go build
```

# Installation/Run

1. Before running scan4all, you must install the libpcap library

```sh
# ubuntu、linux
apt update
apt install -yy libpcap0.8-dev
sudo apt install -y libpcap-dev
# cent os
yum install -yy glibc-devel.x86_64
yum install -yy libpcap
# mac os
brew install libpcap

```

2. Go to
[https://github.com/hktalent/scan4all/releases/](https://github.com/hktalent/scan4all/releases/)
Download the latest scan4all release and run it:

## Runtime dynamic library version issues

If you encounter the error `libpcap.so.0.8: cannot open shared object file: No such file or directory` when running

Please first check whether the libpcap library is installed correctly.
```sh
ls -all /lib64/libpcap*
```
If another version of the libpcap library is installed, you can create a symbolic link to /lib64/libpcap.so.0.8 for the program to run normally.

```sh
ln -s /lib64/libpcap.so.1.9.1 /lib64/libpcap.so.0.8
```

## docker ubuntu
```bash 
apt update;apt install -yy libpcap0.8-dev
```
## centos
```bash
yum install -yy glibc-devel.x86_64
```
### linux
too many open files
Check the current number of open files
```
awk '{print $1}' /proc/sys/fs/file-nr
ulimit -a
ulimit -n 819200
```
