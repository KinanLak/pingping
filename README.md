# PingPing

PingPing is a high-performance, multithreaded ping scanner designed for rapid IP range testing.

## Features

-   Fast scanning of IP ranges
-   Up to 3 retry attempts per IP
-   Failed IPs exported to `failed_ips.txt`

## Usage

```bash
./pingping <start_IP> <end_IP> [number_of_threads]
```

Example:

```bash
./pingping 192.168.1.1 192.168.1.254 64
```

## Compilation

```bash
g++ -std=c++11 -pthread pingping.cpp -o pingping
```

## Notes

-   Run with `sudo` to use raw sockets.
-   Without root privileges, the system `ping` command will be used.
