# PCAP Publisher

## Compile for x86
libpcap requires bison and flex:
```sh
sudo apt-get install bison flex
```

```sh
zig build -Dtarget=x86_64-linux-musl -Doptimize=ReleaseSafe
```

## Compile for Raspberry Pi
Static build is not working, because `arm_arch.h` does not exist in OpenSSL package.
```sh
zig build -Dtarget=aarch64-linux-musl -Doptimize=ReleaseSafe
```

Instead use system package mode and link against paho-mqtt-c and libpcap from the package repository:
```sh
sudo apt-get install libpaho-mqtt-dev libssl-dev libpcap-dev
```

Zig currently assumes a pagesize of 4096 on aarch64, but the Raspberry Pi changed it to 16384:
getconf PAGESIZE

sudo nano /boot/firmware/config.txt
Add the following line: `kernel=kernel8.img`

```sh
zig build -Doptimize=ReleaseSafe -fsys=paho-mqtt -fsys=pcap
```

If the option `-Dtarget=aarch64-linux-musl` is passed, the "paths_first" strategy won't work
and Zig will not find libraries from the package repository.
