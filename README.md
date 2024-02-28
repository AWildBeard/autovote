## Example of an autovoting bot
This bot has the ability to bypass a fairly common defensive mechanism for protecting voting forms. 

The main requirements are that you have a CapSolver api token and Wireguard configs in a special format.

For the Wireguard config, have the [Interface] section at the top as normal, except add a netmask to the interface 
addresses and add a bunch of [Peer] elements. See the example. The code will randomly cycle through the provided peers
accessing the target site and submitting votes to the target site. It would be fairly easy to get this code to also
route CapSolver queries through the Wireguard tunnels

```ini
[Interface]
Address = your_ip4_addr/32,your_ip6_addr/128
PrivateKey = your_wireguard_private_key
MTU = 1320
DNS = dns_v4_addr, dns_v6_addr

[Peer]
PublicKey = peers_public_key
PresharedKey = preeshared_key_if_ya_got_it
Endpoint = peer_endpoint
AllowedIPs = 0.0.0.0/0,::/0
PersistentKeepalive = 15

[Peer]
PublicKey = peers_public_key
PresharedKey = preeshared_key_if_ya_got_it
Endpoint = peer_endpoint
AllowedIPs = 0.0.0.0/0,::/0
PersistentKeepalive = 15

[Peer]
PublicKey = peers_public_key
PresharedKey = preeshared_key_if_ya_got_it
Endpoint = peer_endpoint
AllowedIPs = 0.0.0.0/0,::/0
PersistentKeepalive = 15
```