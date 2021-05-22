// Copyright 2020-2021
// pingA - Advanced network diagnostic tool for Golang with MQTT support.
// https://github.com/artlevitan/pingA
//
// Mikhail Kalinin mx10@mail.ru
// Arthur Levitan https://www.levitan.su/

package main

import (
	"bufio"
	"crypto/sha1"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"math"
	"os"
	userinfo "os/user"
	"reflect"
	"runtime"
	"strings"
	"time"

	"github.com/denisbrodbeck/machineid"
	MQTT "github.com/eclipse/paho.mqtt.golang"
	"github.com/fatih/color"
	externalip "github.com/glendc/go-external-ip"
	"github.com/go-ping/ping"
	"gopkg.in/ini.v1"
)

const (
	appName    string = "pingA"                                       // Application Name
	appVersion string = "0.2.0"                                       // Application Version
	welcomeMsg string = "The application is running. Please, wait..." // Start Message
	appLink    string = "https://github.com/artlevitan/pingA"         // Home URL
	//
	// Default Options
	maxProcs       int    = 1            // How many PC Cores to use
	configFileName string = "config.ini" // Name of Config File
	logFileName    string = "pinga.log"  // Name of Log File
	logLimit       int    = 10           // Number of recent log entries
	windowsSupport bool   = false        // Windows Support (true for Windows, false - Linux, Mac)
	//
	// Ping Options
	defaulPingRequests          int           = 4  // Default Number of ICMP Echo Requests to send
	maxPingRequests             int           = 16 // Max Number of ICMP Echo Requests to send
	disConnectedDelay           time.Duration = 5  // [seconds] Delay when communication loss
	connectionTimeoutExternalIP time.Duration = 5  // [seconds] The Time during which the client tries to get its external IP address
	connectionTimeoutPinger     time.Duration = 5  // [seconds] The Time during which the attempt to send ICMP
	connectionDelayByHost       time.Duration = 5  // [seconds] Delay between connections in hosts
	//
	// MQTT Options
	qos             int    = 0         // Quality of Service (QoS) in MQTT messaging
	topicPrefix     string = "pingA/"  // Prefix for MQTT Topic Name
	defaultUserID   string = "unknown" // Default Unique ID of the client device
	defaultSourceID string = "unknown" // Default Unique ID of the client device
	// Messages
	loggerInitError string = "Could not initialize Logger"                                                           // Error Message
	configFound     string = "Found configuration file.\nConnection will be made with the settings from the config." // Success Message
	connectionOk    string = "Successful Internet connection"                                                        // Success Message
	connectionLost  string = "Lost Internet connection"                                                              // Error Message
	pleaseWait      string = "Reconnecting. Please, wait..."                                                         // Error Message
)

var (
	logger      *log.Logger
	isConnected bool = true // Internet connection status
)

// generateSHA1Hash - sha1-hash
// @return 40 character string
func generateSHA1Hash(text string) string {
	hasher := sha1.New()
	hasher.Write([]byte(text))
	return hex.EncodeToString(hasher.Sum(nil))
}

// itemExists - checks for an element in a slice
func itemExists(slice interface{}, item interface{}) bool {
	s := reflect.ValueOf(slice)
	for i := 0; i < s.Len(); i++ {
		if s.Index(i).Interface() == item {
			return true
		}
	}
	return false
}

// durationToString - time.Duration to string
func durationToString(t time.Duration) string {
	return fmt.Sprintf("%.3f", float32(float32(t)/float32(time.Millisecond)))
}

// readLog - Read Logger
// lines int - Number of recent entries
func readLog(lines int) []string {
	if lines == 0 {
		return []string{}
	}
	// Else
	f, _ := os.Open(logFileName)
	defer f.Close()
	fileScanner := bufio.NewScanner(f)
	fileScanner.Split(bufio.ScanLines)
	var ss []string
	for fileScanner.Scan() {
		ss = append(ss, fileScanner.Text())
	}
	// Log Revers
	last := len(ss) - 1
	for i := 0; i < len(ss)/2; i++ {
		ss[i], ss[last-i] = ss[last-i], ss[i]
	}
	// Check Log Length
	if lines > len(ss) {
		lines = len(ss)
	}
	lss := ss[:lines]
	return lss
}

// getExternalIP - client external IP
func getExternalIP() (string, error) {
	// Create the default consensus,
	// using the default configuration and no logger.
	cfg := externalip.ConsensusConfig{
		Timeout: connectionTimeoutExternalIP * time.Second,
	}
	consensus := externalip.DefaultConsensus(&cfg, nil)
	// Get your IP,
	// which is never <nil> when err is <nil>.
	ip, err := consensus.ExternalIP()
	if err != nil {
		return "localhost", err
	}
	return ip.String(), nil
}

// pinger - ping function
// addr string - Host or IP
// n int - Number of ICMP Echo Requests to send
func pinger(addr string, n int) *ping.Statistics {
	pinger, err := ping.NewPinger(addr)
	if err != nil {
		// Panic to throw Connection Error
		panic(err.Error())
	}
	// Timeout
	pinger.Timeout = time.Duration(n) * connectionTimeoutPinger * time.Second
	// Windows Support
	pinger.SetPrivileged(windowsSupport)
	//
	pinger.Count = n
	pinger.Run()                 // blocks until finished
	stats := pinger.Statistics() // get send/receive/rtt stats
	return stats
}

// recovery - middleware recovers from any panics and write log
func recovery(mqttOpts *MQTT.ClientOptions, ipAddresses []string, n int, mqtt string, p string, user string, pass string, log int) {
	if err := recover(); err != nil {
		warningColor := color.New(color.FgWhite, color.BgRed)
		warningColor.Println(connectionLost)
		fmt.Println(pleaseWait)
		fmt.Println()
		// Write to Log
		if isConnected {
			logger.Println(connectionLost)
		}
		isConnected = false
	}

	// Delay
	time.Sleep(disConnectedDelay * time.Second)

	// Recover
	pingA(mqttOpts, ipAddresses, n, mqtt, p, user, pass, log)
}

// pingA - main function that performs the main tasks of the application
func pingA(mqttOpts *MQTT.ClientOptions, ipAddresses []string, n int, mqtt string, p string, user string, pass string, log int) {
	// Panic Recover
	defer recovery(mqttOpts, ipAddresses, n, mqtt, p, user, pass, log)

	// Get Data
	//
	// Client External IP
	clientIP, clientIPError := getExternalIP()
	found := itemExists(ipAddresses, clientIP)
	if !found && clientIPError == nil {
		ipAddresses = append(ipAddresses, clientIP)
	}

	// User Name
	var userID string
	currentUser, err := userinfo.Current()
	if err != nil {
		userID = defaultUserID
	} else {
		userID = generateSHA1Hash(currentUser.Username)
	}

	// Unique ID of the client device
	var sourceID string
	sourceID, err = machineid.ID()
	if err != nil {
		sourceID = defaultSourceID
	} else {
		sourceID = generateSHA1Hash(sourceID)
	}

	for i := range ipAddresses {
		// Ping Results
		pingResult := pinger(ipAddresses[i], n)

		ipAddr := pingResult.IPAddr.IP.String()                            // IPAddr is the address of the host being pinged.
		packetsSent := pingResult.PacketsSent                              // PacketsSent is the number of packets sent
		packetsRecv := pingResult.PacketsRecv                              // PacketsRecv is the number of packets received
		rtts := pingResult.Rtts                                            // Rtts is all of the round-trip times sent via this pinger
		minRtt := durationToString(pingResult.MinRtt)                      // MinRtt is the minimum round-trip time sent via this pinger
		maxRtt := durationToString(pingResult.MaxRtt)                      // MaxRtt is the maximum round-trip time sent via this pinger
		avgRtt := durationToString(pingResult.AvgRtt)                      // AvgRtt is the average round-trip time sent via this pinger
		stdDevRtt := durationToString(pingResult.StdDevRtt)                // StdDevRtt is the standard deviation of the round-trip times sent via this pinger
		packetLoss := fmt.Sprintf("%.1f", math.Abs(pingResult.PacketLoss)) // PacketLoss is the percentage of packets lost
		jitter := durationToString(pingResult.MaxRtt - pingResult.MinRtt)  // Jitter is the deviation from true periodicity of a presumably periodic signal

		// Publish to console
		color.Cyan(fmt.Sprintf("--- PING %s (%s) statistics ---", ipAddresses[i], ipAddr))
		// rtts
		for i := range rtts {
			rtt := durationToString(rtts[i])
			fmt.Printf("rtts: icmp_seq=%d time=%v ms\n", i+1, rtt)
		}
		fmt.Printf("%d packets transmitted, %d packets received, %v%% packet loss, %v ms Jitter\n", packetsSent, packetsRecv, packetLoss, jitter)
		fmt.Printf("round-trip min/avg/max/stddev = %v/%v/%v/%v ms\n", minRtt, avgRtt, maxRtt, stdDevRtt)
		fmt.Println()
		// End publish to console

		// Publish data to MQTT
		var token MQTT.Token
		if mqtt != "" {
			// MQTT
			// Create MQTT Client
			client := MQTT.NewClient(mqttOpts)
			if token = client.Connect(); token.Wait() && token.Error() != nil {
				// Panic to throw Connection Error
				panic(token.Error())
			}

			// Prepare Topics
			topic := topicPrefix + user + "/" + ipAddr + "/"
			topicUserID := topic + "user_id"
			topicSourceID := topic + "source_id"
			topicSourceIP := topic + "source_ip"
			topicRtts := topic + "rtts"
			topicPacketLoss := topic + "packet_loss"
			topicJitter := topic + "jitter"
			topicLog := topicPrefix + "log/" + user + "/"

			// Publish
			client.Publish(topicUserID, byte(qos), false, userID)
			client.Publish(topicSourceID, byte(qos), false, sourceID)
			client.Publish(topicSourceIP, byte(qos), false, clientIP)
			for j := range rtts {
				rtt := durationToString(rtts[j])
				client.Publish(topicRtts, byte(qos), false, rtt)
			}
			client.Publish(topicPacketLoss, byte(qos), false, packetLoss)
			client.Publish(topicJitter, byte(qos), false, jitter)
			color.Green("Information was successfully sent to the MQTT topic: %s", topic)
			fmt.Println()
			// Sending Log
			lss := readLog(log)
			for ls := range lss {
				client.Publish(topicLog, byte(qos), false, lss[ls])
			}
			//
			token.Wait()
			client.Disconnect(250)
		}
		// After Ping Results
		// Write to Log
		if !isConnected {
			logger.Println(connectionOk)
			//
			successColor := color.New(color.FgWhite, color.BgGreen)
			successColor.Println(connectionOk)
			fmt.Println()
		}
		isConnected = true
		// Delay
		time.Sleep(connectionDelayByHost * time.Second)
	}
}

func main() {
	// How many PC cores to use
	runtime.GOMAXPROCS(maxProcs)

	// Init Logger
	f, err := os.OpenFile(logFileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		color.Red(loggerInitError)
		fmt.Println(err.Error())
		os.Exit(1)
	}
	defer f.Close()
	logger = log.New(f, "", log.LstdFlags)

	// Welcome Message
	fmt.Printf("%s [v%s]\n%s\n", appName, appVersion, appLink)
	fmt.Println(welcomeMsg)
	fmt.Println()

	// Get Console Flags
	var ip string   // List of IP addresses (separate by comma if multiple values: host1.com,host2.com)
	var n int       // Number of ICMP Echo Requests to send
	var mqtt string // MQTT Server
	var p string    // MQTT Port
	var user string // User Name & MQTT Login authentication
	var pass string // MQTT Password authentication
	var log int     // Number of ICMP Echo Requests to send

	// Read Console Flags
	flag.StringVar(&ip, "ip", "", "List of IP addresses (separate by comma if multiple values: host1.com,host2.com)")
	flag.IntVar(&n, "n", defaulPingRequests, "Number of ICMP Echo Requests to send")
	flag.StringVar(&mqtt, "mqtt", "", "MQTT Server")
	flag.StringVar(&p, "p", "1883", "MQTT Port")
	flag.StringVar(&user, "user", "", "User Name & MQTT Login authentication")
	flag.StringVar(&pass, "pass", "", "MQTT Password authentication")
	flag.IntVar(&log, "log", 0, "The number of recent log entries")
	flag.Parse()

	// Read Config
	cfg, isCfg := ini.Load(configFileName)
	if isCfg == nil {
		color.Yellow(configFound)
		fmt.Println()
		//
		ip = cfg.Section("").Key("ip").String()
		n, _ = cfg.Section("").Key("n").Int()
		mqtt = cfg.Section("").Key("mqtt").String()
		p = cfg.Section("").Key("p").String()
		user = cfg.Section("").Key("user").String()
		pass = cfg.Section("").Key("pass").String()
		log, _ = cfg.Section("").Key("log").Int()
	}

	// IP addresses
	var ipAddresses []string
	if ip != "" {
		ipAddresses = strings.Split(ip, ",")
	}

	// Limit Number of ICMP Echo Requests to send
	if n > maxPingRequests {
		n = defaulPingRequests
	}

	// Limit Number of recent log entries
	if log > logLimit {
		log = logLimit
	}

	// Choosing a place to publish data
	var mqttOpts *MQTT.ClientOptions
	if mqtt != "" {
		// MQTT
		//
		// Generate unique ClientID
		clientID := user + "-" + generateSHA1Hash(fmt.Sprintf("%v", time.Now().Format(time.StampNano)))
		//
		// Connection Options
		mqttOpts = MQTT.NewClientOptions()
		mqttOpts.AddBroker("tcp://" + mqtt + ":" + p)
		mqttOpts.SetClientID(clientID)
		mqttOpts.SetUsername(user)
		mqttOpts.SetPassword(pass)
		mqttOpts.SetCleanSession(false)
	}

	// Start pingA
	pingA(mqttOpts, ipAddresses, n, mqtt, p, user, pass, log)
}
