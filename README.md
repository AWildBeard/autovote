## Autovote bot
*Different bots are on different branches*  
Bot-specific instructions can be found on those branches

This bot is for;
```azure
 ██████ ██       █████  ███    ██ ██      ██ ███████ ████████ 
██      ██      ██   ██ ████   ██ ██      ██ ██         ██    
██      ██      ███████ ██ ██  ██ ██      ██ ███████    ██    
██      ██      ██   ██ ██  ██ ██ ██      ██      ██    ██    
 ██████ ███████ ██   ██ ██   ████ ███████ ██ ███████    ██  
```
This bot will bypass the human check on the website.

The main requirements are that you have a CapSolver api token and Wireguard configs in a special format.

For the Wireguard config;
1) You must use the same `[Interface]` (`PrivateKey`, `Address`, etc.) for all the `[Peer]`s you want to connect to. The code will not read more than one `[Interface]` section from the unified config.
2) Make sure a netmask is on each `[Interface]` `Address`

See the example below...

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

Once you have;
1) Your unified Wireguard config similar to the above
2) CapSolver key
3) A target account to vote for (can be found in the URL on the page you are voting for)

Kickoff the bot with
```shell
./autovote -C 'CAPSOLVER_API_TOKEN' -a 'Name of account to vote for'
```

For a full list of options, check out `./autovote -h`