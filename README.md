# pingA

Advanced network diagnostic tool with MQTT support.

## Installation

```bash
go get github.com/denisbrodbeck/machineid
go get github.com/eclipse/paho.mqtt.golang
go get github.com/glendc/go-external-ip
go get github.com/sparrc/go-ping
```

## Usage

```golang
 -ip string
        List of IP addresses (separate by comma if multiple values: host1.com,host2.com)
  -log int
        The number of recent log entries
  -mqtt string
        MQTT Server
  -n int
        Number of ICMP Echo Requests to send (default 4)
  -p string
        MQTT Port (default "1883")
  -pass string
        MQTT Password authentication
  -user string
        User Name & MQTT Login authentication
```

## Build options
### Linux
```golang
windowsSupport bool = false
```
```bash
env GOOS=linux GOARCH=amd64 go build
```
### Mac
```golang
windowsSupport bool = false
```
```bash
env GOOS=darwin GOARCH=amd64 go build
```
### For Windows
```golang
windowsSupport bool = true
```
```bash
env GOOS=windows GOARCH=amd64 go build
```
### Other compilation options
#### $GOOS

| OS            | $GOOS     |
|---------------|-----------|
| Linux         | linux     |
| MacOS X       | darwin    |
| Windows       | windows   |
| FreeBSD       | freebsd   |
| NetBSD        | netbsd    |
| OpenBSD       | openbsd   |
| DragonFly BSD | dragonfly |
| Plan 9        | plan9     |
| Native Client | nacl      |
| Android       | android   |

#### $GOARCH

| Architecture           | $GOARCH  |
|------------------------|----------|
| x386                   | 386      |
| AMD64                  | amd64    |
| AMD64 с 32-указателями | amd64p32 |
| ARM                    | arm      |

## License
[MIT](https://choosealicense.com/licenses/mit/)