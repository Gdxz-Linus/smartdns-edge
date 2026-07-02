# Module 7: Smart Split-Routing & Client Control

SmartDNS Edge offers multi-dimensional intelligent split-routing. You can selectively route queries based on domain names or enforce strictly independent network rules (such as parental controls) based on the IP or MAC addresses of different devices in your LAN.

## 7.1 Domain Split-Routing & Groups

By grouping upstream servers and mapping specific domain suffixes to those groups, you can easily achieve perfect split routing (e.g., domestic domains via local DNS, overseas domains via encrypted offshore DNS).

   1. Configure independent resolution groups for domestic and overseas traffic:

    ```shell
    # Configure local upstream, add to 'cn' group, and exclude from the default global pool
    server 119.29.29.29 -group cn -exclude-default-group
    
    # Configure overseas upstream, add to 'overseas' group, and exclude from the default pool
    server-tls 8.8.8.8:853 -group overseas -exclude-default-group
    
    # Forcefully route specific domains to their corresponding groups
    nameserver /.cn/cn
    nameserver /google.com/overseas
    ```

   2. You can also achieve coarse-grained port-based routing (often used with soft-router plugins):

    ```shell
    # All queries sent to port 7053 will exclusively use the 'overseas' group
    bind :7053 -group overseas
    
    # All queries sent to port 8053 will exclusively use the 'cn' group
    bind :8053 -group cn
    ```

## 7.2 Rule Groups Configuration

When defining a large set of conditions for a specific scenario, you can use `group-begin` and `group-end` to encapsulate an independent scope, making the configuration highly readable.

   Create a standalone rule scope and specify its trigger conditions:

    ```shell
    # Begin a rule group named 'rule-guest' without inheriting global defaults
    group-begin rule-guest -inherit none
    
    # Trigger this group if the query matches a.com OR if the client IP is 192.168.1.100
    group-match -client-ip 192.168.1.100 -domain a.com
    
    # Guests can only use this specific DNS server
    server 223.5.5.5
    
    # Block all video sites for guests
    address /youtube.com/#
    
    group-end
    ```

## 7.3 Client Control & Parental Control

SmartDNS Edge supports targeted access control based on the IP, IP sets, or MAC addresses of requesting devices on your local network.

   Restrict network access behavior for specific devices via MAC or IP:

    ```shell
    # Enable Access Control List (ACL) support
    acl-enable yes
    
    # Bind a dedicated 'child' rule group to a specific MAC address (e.g., child's tablet)
    client-rules 00:11:22:33:44:55 -g child
    
    # Bind a specific IP subnet to the overseas resolution group
    client-rules 192.168.1.10/24 -g overseas
    ```

## 7.4 Local Hostname Resolution (Local Domain & mDNS)

Remembering IP addresses for every device in a home or office intranet is tedious. By enabling local resolution features, you can access LAN devices (like NAS or printers) directly via their hostnames.

   Enable mDNS resolution and set a local domain suffix:

    ```shell
    # Enable mDNS lookup to automatically resolve other smart devices broadcasting on the LAN
    mdns-lookup yes
    
    # Set the local domain suffix. Requests for plain hostnames will have this suffix appended
    local-domain home.lan
    ```