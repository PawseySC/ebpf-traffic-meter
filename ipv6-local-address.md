# Local IPv6 addresses

When specifying a local IPv6 address, the format depends on whether you are just writing the address string or if you need to include the network interface (like `eth0` or `wlan0`).

Here is the standard way to write and use local IPv6 addresses.

### 1. The Basic Format
An IPv6 address consists of 8 groups of 4 hexadecimal digits (0–9, A–F) separated by colons.
*   **Total length:** 128 bits.
*   **Compression:** You can replace one sequence of zeros with a double colon (`::`), but you can only do this **once** in an address.

**Standard Local Address:**
```text
2001:0db8:85a3:0000:0000:8a2e:0370:7334
```

**Compressed (Standard):**
```text
2001:db8:85a3:0:0:8a2e:370:7334
```

---

### 2. "Local" Address Types
"Local" usually refers to one of two specific address ranges:

#### A. Link-Local Address (Most Common)
Used for communication within the same local network segment. These start with `fe80:`.
*   **Format:** `fe80::1` (The `1` is the loopback/host number).
*   **Usage:** Often requires the interface name to be specified because multiple interfaces can have the same Link-Local address.

#### B. Unique Local Address (ULA)
Used for private networks (similar to IPv4 `192.168.x.x`). These start with `fc` or `fd`.
*   **Format:** `fd12:3456:789a::1`

---

### 3. How to specify the Interface
If you are using this in a **Command Line** (like `ping`, `curl`, or `ssh`), you must specify which network interface the address belongs to, or the computer won't know which "wire" to send the packet on.

**Syntax:** `[Address]%[InterfaceName]`

*   **Example (Linux/macOS):**
    To ping your local address on the `eth0` interface:
    ```bash
    ping6 fe80::1%eth0
    ```
    *(Note the `%eth0` at the end).*

*   **Example (Windows):**
    Windows uses a different syntax for link-local addresses:
    ```cmd
    ping -6 fe80::1%1
    ```

### 4. Common Examples

| Type | Address | Description |
| :--- | :--- | :--- |
| **Loopback** | `::1` | The local machine itself (equivalent to `127.0.0.1`). |
| **Link-Local** | `fe80::1` | Local to the network segment. |
| **ULA** | `fd12:3456:789a::1` | Private network address. |
| **Compressed** | `2001:db8::1` | Standard compressed notation. |

### Summary Checklist
1.  **Omit** leading zeros in each group (e.g., `db8` instead of `0db8`).
2.  **Use** `::` to compress the longest continuous sequence of zeros.
3.  **Add** `%InterfaceName` (e.g., `%eth0`) if you are running a command on the CLI.
