package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/MakeNowJust/heredoc/v2"
	"github.com/go-ini/ini"
	"github.com/spf13/pflag"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"io"
	"math/rand"
	"net/http"
	"net/http/cookiejar"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"time"
)

var (
	vpnConfigPath       string
	voteCountMin        uint
	voteCountMax        uint
	targetAccount       string
	profileURL          string
	requestTimeout      time.Duration
	floatTimeMin        time.Duration
	floatTimeMax        time.Duration
	printVersionAndExit bool

	buildType    string
	buildVersion string
)

func init() {
	pflag.StringVarP(&vpnConfigPath, "config", "c", "config.conf",
		"The file to parse a multi-peer Wireguard config from.")
	pflag.UintVarP(&voteCountMin, "min-votes", "v", 16,
		"Minimum number of votes to issue to ClanList. The total number of votes to cast is randomized between "+
			"this flag and the --max-votes (-V) flag.")
	pflag.UintVarP(&voteCountMax, "max-votes", "V", 20,
		"Maximum number of votes to issue to ClanList. The total number of votes to cast is randomized between "+
			"this flag and the --min-votes (-v) flag.")
	pflag.StringVarP(&profileURL, "profile", "p", "",
		"Profile page to request before requesting anything else. Just used to at least *try* to make it look real.")
	pflag.StringVarP(&targetAccount, "account", "a", "",
		"Account ID to vote for. This can be found in the POST request when voting.")
	pflag.DurationVarP(&requestTimeout, "timeout", "t", 30*time.Second,
		"Time to wait for a HTTP request to complete. Leaving this high should be fine.")
	pflag.DurationVarP(&floatTimeMin, "min-float-Time", "f", 6*time.Minute,
		"Minimum time between attempting to vote. Exactly when the attempt is made is randomized between "+
			"this flag and the --max-float-time (-F) flag.")
	pflag.DurationVarP(&floatTimeMax, "max-float-time", "F", 20*time.Minute,
		"Maximum time between attempting to vote. Exactly when the attempt is made is randomized between "+
			"this flag and the --min-float-time (-f) flag.")
	pflag.BoolVar(&printVersionAndExit, "version", false,
		"Print version information then exit")
}

func getConfig(c string) (*DeviceConfig, error) {
	loadOptions := ini.LoadOptions{AllowNonUniqueSections: true}
	iniFile, err := ini.LoadSources(loadOptions, c)
	if err != nil {
		err = fmt.Errorf("failed to read config %v: %v", c, err)
		return nil, err
	}

	newDevConfig := &DeviceConfig{
		Peers:     make([]PeerConfig, 0),
		Addresses: make([]netip.Addr, 0),
		DNS:       make([]netip.Addr, 0),
	}

	err = ParseInterface(iniFile, newDevConfig)
	if err != nil {
		err = fmt.Errorf("failed to parse wireguard interface settings from %v: %v", c, err)
		return nil, err
	}

	err = ParsePeers(iniFile, &newDevConfig.Peers)
	if err != nil {
		err = fmt.Errorf("failed to parse wireguard peer settings from %v: %v", c, err)
		return nil, err
	}

	return newDevConfig, err
}

type WireguardRoutedHttpClient struct {
	SourceAddress string
	http.Client
	*netstack.Net
}

func NewWireguardRoutedHttpClient(netstack *netstack.Net, perRequestTimeout time.Duration) (*WireguardRoutedHttpClient, []error) {
	client := &WireguardRoutedHttpClient{
		Net: netstack,
	}

	errors := make([]error, 0)
	customTransport := http.DefaultTransport.(*http.Transport)
	customTransport.Dial = netstack.Dial
	customTransport.DialContext = netstack.DialContext

	jar, err := cookiejar.New(nil)
	if err != nil {
		panic(err)
	}

	client.Client = http.Client{
		Transport:     customTransport,
		CheckRedirect: nil,
		Jar:           jar,
		Timeout:       0,
	}

	// This should never fail
	ctxt, cncl := context.WithTimeout(context.Background(), perRequestTimeout)
	req, err := http.NewRequestWithContext(ctxt, http.MethodGet, "https://ipconfig.io/ip", nil)
	if err != nil {
		panic(err)
	}

	rsp, err := client.Do(req)
	cncl()
	if err != nil /*&& !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded)*/ {
		errors = append(errors, err)
		ctxt, cncl = context.WithTimeout(context.Background(), perRequestTimeout)
		req, err = http.NewRequestWithContext(ctxt, http.MethodGet, "https://ifconfig.io/ip", nil)
		if err != nil {
			panic(err)
		}

		rsp, err = client.Do(req)
		cncl()
		if err != nil {
			errors = append(errors, err)
			ctxt, cncl = context.WithTimeout(context.Background(), perRequestTimeout)
			req, err = http.NewRequestWithContext(ctxt, http.MethodGet, "https://ipinfo.io/ip", nil)
			if err != nil {
				panic(err)
			}

			rsp, err = client.Do(req)
			cncl()
			if err != nil {
				errors = append(errors, err)
				return nil, errors
			}
		}
	}

	bodyReader := bufio.NewReader(rsp.Body)
	body, err := io.ReadAll(bodyReader)
	if err != nil {
		panic(err)
	}

	_ = rsp.Body.Close()

	client.SourceAddress = strings.Trim(string(body), "\n")

	return client, nil
}

func main() {
	pflag.Parse()

	if printVersionAndExit {
		fmt.Printf("%v-%v-%v\n", runtime.Version(), buildVersion, buildType)
		os.Exit(0)
	}

	vpnConfig, err := getConfig(vpnConfigPath)
	if err != nil {
		fmt.Printf("failed to read vpn config %v: %v\n", vpnConfigPath, err)
		os.Exit(1)
	}

	if voteCountMax <= voteCountMin {
		fmt.Printf("--vote-count-max (-V) must be greater than --vote-count-min (-v), you supplied %v and %v respectively\n",
			voteCountMax, voteCountMin)
		os.Exit(1)
	}

	if targetAccount == "" {
		fmt.Printf("you must supply a account to vote for with --account (-a)\n")
		os.Exit(1)
	}

	if profileURL == "" {
		fmt.Printf("you must supply a profile URL with --profile (-p)\n")
		os.Exit(1)
	}

	rawTunnel, tunneledNetworkStack, err := netstack.CreateNetTUN(vpnConfig.Addresses, vpnConfig.DNS, vpnConfig.MTU)
	if err != nil {
		fmt.Printf("failed to create tunnel device and tunneled network stack: %v\n", err)
		os.Exit(1)
	}

	tunnelControlDevice := device.NewDevice(rawTunnel, conn.NewDefaultBind(), device.NewLogger(0, ""))

	err = tunnelControlDevice.IpcSet(createInterfaceIPCRequest(vpnConfig))
	if err != nil {
		fmt.Printf("failed to set interface settings: %v\n", err)
		os.Exit(1)
	}

	rand.Shuffle(len(vpnConfig.Peers), func(i, j int) {
		vpnConfig.Peers[i], vpnConfig.Peers[j] = vpnConfig.Peers[j], vpnConfig.Peers[i]
	})

	fmt.Printf("[?] %v peers available for routing \n", len(vpnConfig.Peers))

	doSleep := false
	for voteCount := rand.Intn(int(voteCountMax-voteCountMin)) + int(voteCountMin); voteCount > 0; {
		for _, config := range vpnConfig.Peers {
			if voteCount <= 0 {
				break
			}

			tunnelControlDevice.RemoveAllPeers()

			if doSleep {
				timeToSleep := time.Duration(rand.Int63n(int64(floatTimeMax-floatTimeMin)) + int64(floatTimeMin))
				fmt.Printf("[?] floating for %s before voting again...\n", timeToSleep)
				time.Sleep(timeToSleep)
			} else {
				doSleep = false
			}

			{
				peerRequest := createPeerIPCRequest(&config)
				err = tunnelControlDevice.IpcSet(peerRequest)
				if err != nil {
					fmt.Printf("[-] failed to set peer (%v) settings: %v\n", config.Endpoint, err)
					continue
				}

				err = tunnelControlDevice.Up()
				if err != nil {
					panic(err)
				}
			}

			client, errors := NewWireguardRoutedHttpClient(tunneledNetworkStack, requestTimeout)
			if len(errors) > 0 {
				fmt.Printf("[-] peer %v failed connectivity test:\n", *config.Endpoint)
				for _, err := range errors {
					fmt.Printf("\t%v\n", err)
				}

				continue
			} else {
				fmt.Printf("[+] peer %v succeeded connectivity test with external IP %v\n", *config.Endpoint, client.SourceAddress)
			}

			// Do the base request to milsimunits to look semi-real, not really trying, but not not trying either
			ctxt, cncl := context.WithTimeout(context.Background(), requestTimeout)
			req, err := http.NewRequestWithContext(ctxt, http.MethodGet, profileURL, nil)
			if err != nil {
				panic(err)
			}

			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0")
			req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9")
			req.Header.Set("Accept-Language", "en-US,en;q=0.5")
			req.Header.Set("Sec-Fetch-Dest", "document")
			req.Header.Set("Sec-Fetch-Mode", "navigate")
			req.Header.Set("Sec-Fetch-Site", "cross-site")

			if milsimunitsRsp, err := client.Do(req); err == nil {
				fmt.Printf("[+] got profile page\n")
				_ = milsimunitsRsp.Body.Close()
			} else {
				fmt.Printf("[-] failed to connect to milsimunits: %v\n", err)
				continue
			}

			// Take a break, to simulate teh humanns. Sleep at least 6 seconds, up to a max of 30 seconds
			{
				timeToSleep := time.Duration(rand.Intn(14)+6) * time.Second
				fmt.Printf("[?] backing off for %s for 'realism'\n", timeToSleep)
				time.Sleep(timeToSleep)
			}

			content, err := json.Marshal(struct {
				UnitId string `json:"unitId"`
			}{UnitId: targetAccount})
			if err != nil { // This should blatantly never occur
				panic(err)
			}

			ctxt, cncl = context.WithTimeout(context.Background(), requestTimeout)
			req, err = http.NewRequestWithContext(ctxt, http.MethodPost, "https://milsimunits.com/api/vote", bytes.NewReader(content))
			if err != nil {
				panic(err)
			}

			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0")
			req.Header.Set("Accept", "application/json, text/javascript, */*; q=0.01")
			req.Header.Set("Accept-Language", "en-US,en;q=0.5")
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Origin", "https://milsimunits.com")
			req.Header.Set("Pragma", "no-cache")
			req.Header.Set("Referer", profileURL)
			req.Header.Set("Sec-Fetch-Dest", "empty")
			req.Header.Set("Sec-Fetch-Mode", "cors")
			req.Header.Set("Sec-Fetch-Site", "same-origin")

			isContextCancelled := func(ctxt context.Context) bool {
				select {
				case <-ctxt.Done():
					return true
				default:
					return false
				}
			}

			submitted := false
			for retryCount := 3; retryCount >= 0; retryCount-- {
				rsp, err := client.Do(req)
				cncl()
				if err != nil {
					fmt.Printf("[-] failed to submit vote to milsimunits: %v\n", err)
					if isContextCancelled(ctxt) {
						break
					}

					time.Sleep(2 * time.Second)
					continue
				}

				response, err := io.ReadAll(rsp.Body)
				_ = rsp.Body.Close()

				milsimunitsVotes := struct{ Votes int }{}
				err = json.Unmarshal(response, &milsimunitsVotes)
				if err != nil {
					fmt.Printf("[-] failed to submite vote to milsimunits (%s): %v\n", response, err)
					if isContextCancelled(ctxt) {
						break
					}

					time.Sleep(1 * time.Second)
					continue
				}

				submitted = true
				break
			}

			if submitted {
				fmt.Printf("[+] successfully submitted vote to milsimunits\n")
				voteCount = voteCount - 1
				doSleep = true
			}
		}
	}
}

func createInterfaceIPCRequest(conf *DeviceConfig) string {
	var ipcCMD bytes.Buffer

	ipcCMD.WriteString(fmt.Sprintf("private_key=%v\n", conf.SecretKey))

	if conf.ListenPort != nil {
		ipcCMD.WriteString(fmt.Sprintf("listen_port=%v\n", conf.ListenPort))
	}

	return ipcCMD.String()
}

func createPeerIPCRequest(peerConf *PeerConfig) string {
	var ipcCMD bytes.Buffer

	ipcCMD.WriteString("replace_peers=true\n")
	ipcCMD.WriteString(fmt.Sprintf(heredoc.Doc(`
				public_key=%s
				persistent_keepalive_interval=%d
				preshared_key=%s
			`),
		peerConf.PublicKey, peerConf.KeepAlive, peerConf.PreSharedKey,
	))

	if peerConf.Endpoint != nil {
		ipcCMD.WriteString(fmt.Sprintf("endpoint=%s\n", *peerConf.Endpoint))
	}

	if len(peerConf.AllowedIPs) > 0 {
		for _, ip := range peerConf.AllowedIPs {
			ipcCMD.WriteString(fmt.Sprintf("allowed_ip=%s\n", ip.String()))
		}
	} else {
		ipcCMD.WriteString(heredoc.Doc(`
				allowed_ip=0.0.0.0/0
				allowed_ip=::0/0
			`))
	}

	return ipcCMD.String()
}
