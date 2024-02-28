## Autovote bot
*Different bots are on different branches*  
Bot-specific instructions can be found on those branches

This bot is for;
```azure
███    ███ ██ ██      ███████ ██ ███    ███ ██    ██ ███    ██ ██ ████████ ███████ 
████  ████ ██ ██      ██      ██ ████  ████ ██    ██ ████   ██ ██    ██    ██      
██ ████ ██ ██ ██      ███████ ██ ██ ████ ██ ██    ██ ██ ██  ██ ██    ██    ███████ 
██  ██  ██ ██ ██           ██ ██ ██  ██  ██ ██    ██ ██  ██ ██ ██    ██         ██ 
██      ██ ██ ███████ ███████ ██ ██      ██  ██████  ██   ████ ██    ██    ███████ 
```

The main requirement is that you have a Wireguard configs in a special format.

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
2) A target account URL to vote for (can be found in the URL on the page you are voting for)
3) A target account ID to vote for (can be found by submitting a vote request with dev tools open on the network page, see the request info)

Kickoff the bot with
```shell
./autovote -c "path-to-unified-wireguard-config" -a "account ID" -p 'url for account page'
```

For a full list of options, check out `./autovote -h`