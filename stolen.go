// This was stolen from https://github.com/octeep/wireproxy.
// I stole the parsing code for INI type files that they wrote
//
// At the time there was an issue with go1.21 and wireguard-go. This was done as a troubleshooting measure before
// downgrading to go1.20.X which was the solution. Now I can't be bothered to undo the crime.
package main

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"github.com/go-ini/ini"
	_ "golang.zx2c4.com/wireguard/tun"
	"net"
	"net/netip"
	"strings"
)

type PeerConfig struct {
	PublicKey    string
	PreSharedKey string
	Endpoint     *string
	KeepAlive    int
	AllowedIPs   []netip.Prefix
}

// DeviceConfig contains the information to initiate a wireguard connection
type DeviceConfig struct {
	SecretKey  string
	Addresses  []netip.Addr
	Peers      []PeerConfig
	DNS        []netip.Addr
	MTU        int
	ListenPort *int
}

func parseString(section *ini.Section, keyName string) (string, error) {
	key := section.Key(keyName)
	if key == nil {
		return "", errors.New(keyName + " should not be empty")
	}
	return key.String(), nil
}

func parseBase64KeyToHex(section *ini.Section, keyName string) (string, error) {
	key, err := parseString(section, keyName)
	if err != nil {
		return "", err
	}
	result, err := encodeBase64ToHex(key)
	if err != nil {
		return result, err
	}

	return result, nil
}

func encodeBase64ToHex(key string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return "", errors.New("invalid base64 string: " + key)
	}
	if len(decoded) != 32 {
		return "", errors.New("key should be 32 bytes: " + key)
	}
	return hex.EncodeToString(decoded), nil
}

func parseNetIP(section *ini.Section, keyName string) ([]netip.Addr, error) {
	key := section.Key(keyName)
	if key == nil {
		return []netip.Addr{}, nil
	}

	var ips []netip.Addr
	for _, str := range key.StringsWithShadows(",") {
		str = strings.TrimSpace(str)
		ip, err := netip.ParseAddr(str)
		if err != nil {
			return nil, err
		}
		ips = append(ips, ip)
	}
	return ips, nil
}

func parseCIDRNetIP(section *ini.Section, keyName string) ([]netip.Addr, error) {
	key := section.Key(keyName)
	if key == nil {
		return []netip.Addr{}, nil
	}

	var ips []netip.Addr
	for _, str := range key.StringsWithShadows(",") {
		prefix, err := netip.ParsePrefix(str)
		if err != nil {
			return nil, err
		}

		addr := prefix.Addr()
		ips = append(ips, addr)
	}
	return ips, nil
}

func parseAllowedIPs(section *ini.Section) ([]netip.Prefix, error) {
	key := section.Key("AllowedIPs")
	if key == nil {
		return []netip.Prefix{}, nil
	}

	var ips []netip.Prefix
	for _, str := range key.StringsWithShadows(",") {
		prefix, err := netip.ParsePrefix(str)
		if err != nil {
			return nil, err
		}

		ips = append(ips, prefix)
	}
	return ips, nil
}

func resolveIP(ip string) (*net.IPAddr, error) {
	return net.ResolveIPAddr("ip", ip)
}

func resolveIPPAndPort(addr string) (string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", err
	}

	ip, err := resolveIP(host)
	if err != nil {
		return "", err
	}
	return net.JoinHostPort(ip.String(), port), nil
}

// ParseInterface parses the [Interface] section and extract the information into `device`
func ParseInterface(cfg *ini.File, device *DeviceConfig) error {
	sections, err := cfg.SectionsByName("Interface")
	if len(sections) != 1 || err != nil {
		return errors.New("one and only one [Interface] is expected")
	}
	section := sections[0]

	address, err := parseCIDRNetIP(section, "Address")
	if err != nil {
		return err
	}

	device.Addresses = address

	privKey, err := parseBase64KeyToHex(section, "PrivateKey")
	if err != nil {
		return err
	}
	device.SecretKey = privKey

	dns, err := parseNetIP(section, "DNS")
	if err != nil {
		return err
	}
	device.DNS = dns

	if sectionKey, err := section.GetKey("MTU"); err == nil {
		value, err := sectionKey.Int()
		if err != nil {
			return err
		}
		device.MTU = value
	}

	if sectionKey, err := section.GetKey("ListenPort"); err == nil {
		value, err := sectionKey.Int()
		if err != nil {
			return err
		}
		device.ListenPort = &value
	}

	return nil
}

// ParsePeer parses the [Peer] section and extract the information into `peers`
func ParsePeers(cfg *ini.File, peers *[]PeerConfig) error {
	sections, err := cfg.SectionsByName("Peer")
	if len(sections) < 1 || err != nil {
		return errors.New("at least one [Peer] is expected")
	}

	for _, section := range sections {
		peer := PeerConfig{
			PreSharedKey: "0000000000000000000000000000000000000000000000000000000000000000",
			KeepAlive:    0,
		}

		decoded, err := parseBase64KeyToHex(section, "PublicKey")
		if err != nil {
			return err
		}
		peer.PublicKey = decoded

		if sectionKey, err := section.GetKey("PresharedKey"); err == nil {
			value, err := encodeBase64ToHex(sectionKey.String())
			if err != nil {
				return err
			}
			peer.PreSharedKey = value
		}

		if sectionKey, err := section.GetKey("Endpoint"); err == nil {
			value := sectionKey.String()
			decoded, err = resolveIPPAndPort(strings.ToLower(value))
			if err != nil {
				return err
			}
			peer.Endpoint = &decoded
		}

		if sectionKey, err := section.GetKey("PersistentKeepalive"); err == nil {
			value, err := sectionKey.Int()
			if err != nil {
				return err
			}
			peer.KeepAlive = value
		}

		peer.AllowedIPs, err = parseAllowedIPs(section)
		if err != nil {
			return err
		}

		*peers = append(*peers, peer)
	}

	return nil
}
