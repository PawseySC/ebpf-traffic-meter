# IPv6 Testing

## 1. Ping an IPv6 address
```bash
ping6 -c 5 google.com
# or
ping -6 -c 5 google.com
```

## 2. Curl with IPv6
```bash
curl -6 https://ipv6.google.com
curl -6 https://www.google.com
```

## 3. Use localhost IPv6
```bash
ping6 -c 5 ::1
curl -6 http://[::1]:8080  # if you have a local server
```

## 4. Check if your system has IPv6 connectivity
```bash
ip -6 addr show
ip -6 route show
```

## 5. Test with loopback (no external IPv6 needed)

Terminal 1: start a simple server
```bash
python3 -m http.server 8080 --bind ::
```

Terminal 2: make requests
```bash
curl -6 http://[::1]:8080
```

Then check the log files for IPv6 entries (they'll have addresses like `::1` or `2001:...`).
