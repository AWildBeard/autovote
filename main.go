package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/MakeNowJust/heredoc/v2"
	capsolver "github.com/capsolver/capsolver-go"
	"github.com/go-ini/ini"
	"github.com/spf13/pflag"
	"golang.org/x/net/html"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"io"
	"math/rand"
	"net/http"
	"net/http/cookiejar"
	"net/netip"
	"net/url"
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
	capSolverAPIToken   string
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
	pflag.StringVarP(&capSolverAPIToken, "cap-solver-token", "C", "",
		"API token for CapSolver")
	pflag.StringVarP(&targetAccount, "account", "a", "",
		"Account name to vote for. This can be found in the URL when on the page to vote.")
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

	if capSolverAPIToken == "" {
		fmt.Printf("you must supply a cap solver API token with --cap-solver-token (-C)\n")
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

			// Test if capsolver is online and is ready to receive requests
			{
				errored := false
				for retryCount := 3; retryCount > 0; retryCount-- {
					if errored {
						time.Sleep(2 * time.Second)
					} else {
						errored = true
					}

					ctxt, cncl := context.WithTimeout(context.Background(), requestTimeout)
					req, err := http.NewRequestWithContext(ctxt, http.MethodGet, "https://api.capsolver.com", nil)
					if err != nil {
						panic(err)
					}

					// Don't VPN CapSolver, we could, but it would require messing with their official sdk, which isn't worth it
					rsp, err := http.DefaultClient.Do(req)
					cncl()
					if err != nil {
						fmt.Printf("[-] failed to connect to capsolver (%v tries remaining): %v\n", retryCount, err)
						continue
					}

					if capSolverResponse, err := io.ReadAll(rsp.Body); err == nil {
						_ = rsp.Body.Close()
						status := &struct{ Status string }{}
						err = json.Unmarshal(capSolverResponse, status)
						if err != nil {
							fmt.Printf("[-] failed to unmarshal capsolver response: %v\n", err)
							continue
						}

						if status.Status == "ready" {
							fmt.Printf("[+] capsolver reporting ready\n")
						} else {
							fmt.Printf("[-] capsolver is not ready (retry count: %v) : \"status\":%v\n", retryCount, status.Status)
							continue
						}
					} else {
						fmt.Printf("[-] failed to read capsolver status response (retry count: %v): %v\n", retryCount, err)
						continue
					}

					break
				}
			}

			// Do the base request to ClanList for the ReCaptcha SiteKey and `_token` that is required by ClanList
			ctxt, cncl := context.WithTimeout(context.Background(), requestTimeout)
			req, err := http.NewRequestWithContext(ctxt, http.MethodGet, "https://clanlist.io/vote/"+targetAccount, nil)
			if err != nil {
				panic(err)
			}

			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0")
			req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9")
			req.Header.Set("Accept-Language", "en-US,en;q=0.5")
			req.Header.Set("Sec-Fetch-Dest", "document")
			req.Header.Set("Sec-Fetch-Mode", "navigate")
			req.Header.Set("Sec-Fetch-Site", "cross-site")

			token := ""
			siteKey := ""
			if clanlistRsp, err := client.Do(req); err == nil {
				tokenizer := html.NewTokenizer(clanlistRsp.Body)

				// parse for _token and data-sitekey
			tokenAndSiteKeySearch:
				for token == "" || siteKey == "" {
					tokenType := tokenizer.Next()
					switch tokenType {
					case html.ErrorToken:
						// Invalid HTML encountered
						break tokenAndSiteKeySearch
					case html.StartTagToken:
						tokenElement := tokenizer.Token()
						if tokenElement.Data == "div" {
							for _, attr := range tokenElement.Attr {
								if attr.Key == "data-sitekey" {
									siteKey = attr.Val
								}
							}
						}

						if tokenElement.Data == "input" {
						tokenSearch:
							for _, attr := range tokenElement.Attr {
								if attr.Key == "name" && attr.Val == "_token" {
									for _, attr = range tokenElement.Attr {
										if attr.Key == "value" {
											token = attr.Val
											break tokenSearch
										}
									}
								}
							}
						}
					default:
						continue
					}
				}

				_ = clanlistRsp.Body.Close()
			} else {
				fmt.Printf("[-] failed to connect to clanlist: %v\n", err)
				continue
			}

			if token == "" || siteKey == "" {
				fmt.Printf("[-] failed to find token (found: \"%v\") or sitekey (found: \"%v\")\n", len(token) > 0, len(siteKey) > 0)
				continue
			} else {
				fmt.Printf("[+] found token \"%v\" and sitekey \"%v\"\n", token, siteKey)
			}

			// Take a break, to simulate teh humanns. Sleep at least 6 seconds, up to a max of 30 seconds
			{
				timeToSleep := time.Duration(rand.Intn(14)+6) * time.Second
				fmt.Printf("[?] backing off for %s for 'realism'\n", timeToSleep)
				time.Sleep(timeToSleep)
			}

			// get CapSolver solution
			solver := capsolver.CapSolver{ApiKey: capSolverAPIToken}
			solution, err := solver.Solve(map[string]any{
				"type":       "ReCaptchaV2taskProxyLess",
				"websiteURL": "https://clanlist.io/vote/" + targetAccount,
				"websiteKey": siteKey,
			})

			if err != nil || (solution != nil && solution.ErrorId == 1) {
				if solution != nil {
					fmt.Printf("[-] CapSolver failed: errorid: %v, errorCode: %v, errorDescription: %v, golang error: %v\n", solution.ErrorId, solution.ErrorCode, solution.ErrorDescription, err)
				} else {
					fmt.Printf("[-] CapSolver failed: %v\n", err)
				}

				continue
			}

			gRecaptchaResponse := solution.Solution.GRecaptchaResponse
			fmt.Print("[+] got recaptcha response from CapSolver\n")

			// Make the POST to ClanList to do the vote
			formValues := url.Values{}
			formValues.Set("_token", token)
			formValues.Set("g-recaptcha-response", gRecaptchaResponse)
			formValues.Set("username", targetAccount)

			ctxt, cncl = context.WithTimeout(context.Background(), requestTimeout)
			req, err = http.NewRequestWithContext(ctxt, http.MethodPost, "https://clanlist.io/test-v", strings.NewReader(formValues.Encode()))
			if err != nil {
				panic(err)
			}

			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0")
			req.Header.Set("Accept", "application/json, text/javascript, */*; q=0.01")
			req.Header.Set("Accept-Language", "en-US,en;q=0.5")
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
			req.Header.Set("X-Requested-With", "XMLHttpRequest")
			req.Header.Set("Origin", "https://clanlist.io")
			req.Header.Set("Referer", fmt.Sprintf("https://clanlist.io/vote/%v", targetAccount))
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
					fmt.Printf("[-] failed to submit vote to clanlist: %v\n", err)
					if isContextCancelled(ctxt) {
						break
					}

					time.Sleep(2 * time.Second)
					continue
				}

				response, err := io.ReadAll(rsp.Body)
				_ = rsp.Body.Close()

				clanlistSuccess := struct{ Success string }{}
				err = json.Unmarshal(response, &clanlistSuccess)
				if err != nil {
					fmt.Printf("[-] failed to submite vote to clanlist (%s): %v\n", response, err)
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
				fmt.Printf("[+] successfully submitted vote to clanlist\n")
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
