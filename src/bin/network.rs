use std::net::IpAddr;
use get_if_addrs::get_if_addrs;

// Data structure to hold network interface information
pub struct NetworkInterface {
    pub name: String, // Name of the network interface (e.g., "eth0", "wlan0")
    pub ip: String, // IP address
    pub mac: String, // MAC address
    pub status: String, // Status (e.g., "up", "down")
}

// Fetch available network interfaces and their details
pub fn get_network_interfaces() -> Vec<NetworkInterface> {
    let mut interfaces = Vec::new();

    // Attempt to get network interfaces using get_if_addrs crate
    if let Ok(ifaces) = get_if_addrs() {
        for iface in ifaces {
            // Format the IP address (IPv4 or IPv6) as a string
            let ip = match iface.addr.ip() {
                IpAddr::V4(ipv4) => format!("{}", ipv4),
                IpAddr::V6(ipv6) => format!("{}", ipv6),
            };

            interfaces.push(NetworkInterface {
                name: iface.name, // Interface name
                ip, // IP address
                mac: "N/A".to_string(), // MAC address (not available in this context)
                status: if iface.is_up() { "up" } else { "down" }.to_string(), // Interface status
            })
        }
    }

    interfaces
}