// Copyright 2020-05-05
// pingA - Advanced network diagnostic tool
//
// Mikhail Kalinin / mx10@mail.ru
// Arthur Levitan / 1@levitan.su

// Build options
//
// For Linux and Mac
// ! Disable windowsSupport
// env GOOS=linux GOARCH=amd64 go build
// env GOOS=darwin GOARCH=amd64 go build
//
// For Windows
// ! Enable windowsSupport
// env GOOS=windows GOARCH=amd64 go build
//
// see all compilation options https://habr.com/ru/post/249449/

package main

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	userinfo "os/user"
	"reflect"
	"runtime"
	"strings"
	"time"

	"github.com/denisbrodbeck/machineid"
	MQTT "github.com/eclipse/paho.mqtt.golang"
	externalip "github.com/glendc/go-external-ip"
	"github.com/sparrc/go-ping"
)

const (
	appName    string = "pingA"                                       // Application Name
	appVersion string = "0.0.4"                                       // Application Version
	welcomeMsg string = "The application is running. Please, wait..." // Start Message
	//
	// Default Options
	maxProcs       int    = 1           // How many PC Cores to use
	logFileName    string = "pinga.log" // Name of Log File
	windowsSupport bool   = false       // Windows Support (true for Windows, false - Linux, Mac and etc)
	//
	// Ping Options
	defaulPingRequests          int           = 4  // Default Number of ICMP Echo Requests to send
	maxPingRequests             int           = 16 // Max Number of ICMP Echo Requests to send
	disconnectionDelay          time.Duration = 5  // [seconds] Delay when communication loss
	connectionTimeoutExternalIP time.Duration = 5  // [seconds] The Time during which the client tries to get its external IP address
	connectionTimeoutPinger     time.Duration = 5  // [seconds] The Time during which the attempt to send ICMP
	connectionDelayByHost       time.Duration = 1  // [seconds] Delay between connections in hosts
	//
	// MQTT Options
	qos             int    = 0         // Quality of Service (QoS) in MQTT messaging
	topicPrefix     string = "pingA/"  // Prefix for MQTT Topic Name
	defaultUserID   string = "unknown" // Default Unique ID of the client device
	defaultSourceID string = "unknown" // Default Unique ID of the client device
	// Errors
	connectionLost string = "Internet connection lost!"     // Message
	pleaseWait     string = "Reconnecting. Please, wait..." // Message
)

var (
	logger *log.Logger
)

// timeFormat - To format all dates
func timeFormat(t time.Time) string {
	timeString := t.Format("2006/01/02 - 15:04:05")
	return timeString
}

// GenerateSHA1Hash - sha1-hash
// @return 40 character string
func GenerateSHA1Hash(text string) string {
	hasher := sha1.New()
	hasher.Write([]byte(text))
	return hex.EncodeToString(hasher.Sum(nil))
}

// GenerateSHA256Hash - sha256-hash
// @return 64 character string
func GenerateSHA256Hash(text string) string {
	hasher := sha256.New()
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
		// fmt.Println(err.Error())
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

// Recovery - middleware recovers from any panics and write log
func Recovery(mqttOpts *MQTT.ClientOptions, ipAddresses []string, n int, mqtt string, p string, user string, pass string) {
	if err := recover(); err != nil {
		// fmt.Println("Recovery")
	}
	// Catch Errors
	fmt.Println(connectionLost)
	fmt.Println(pleaseWait)
	fmt.Println()
	// Delay
	time.Sleep(disconnectionDelay * time.Second)
	// Recover
	pingA(mqttOpts, ipAddresses, n, mqtt, p, user, pass)
}

// pingA - main function that performs the main tasks of the application
func pingA(mqttOpts *MQTT.ClientOptions, ipAddresses []string, n int, mqtt string, p string, user string, pass string) {
	// Panic Recover
	defer Recovery(mqttOpts, ipAddresses, n, mqtt, p, user, pass)

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
		userID = GenerateSHA1Hash(currentUser.Username)
	}

	// Unique ID of the client device
	var sourceID string
	sourceID, err = machineid.ID()
	if err != nil {
		sourceID = defaultSourceID
	} else {
		sourceID = GenerateSHA1Hash(sourceID)
	}

	for i := range ipAddresses {
		// Ping Results
		pingResult := pinger(ipAddresses[i], n)

		ipAddr := fmt.Sprintf("%s", pingResult.IPAddr)           // IPAddr is the address of the host being pinged.
		packetsSent := pingResult.PacketsSent                    // PacketsSent is the number of packets sent
		packetsRecv := pingResult.PacketsRecv                    // PacketsRecv is the number of packets received
		rtts := pingResult.Rtts                                  // Rtts is all of the round-trip times sent via this pinger
		minRtt := durationToString(pingResult.MinRtt)            // MinRtt is the minimum round-trip time sent via this pinger
		maxRtt := durationToString(pingResult.MaxRtt)            // MaxRtt is the maximum round-trip time sent via this pinger
		avgRtt := durationToString(pingResult.AvgRtt)            // AvgRtt is the average round-trip time sent via this pinger
		stdDevRtt := durationToString(pingResult.StdDevRtt)      // StdDevRtt is the standard deviation of the round-trip times sent via this pinger
		packetLoss := fmt.Sprintf("%.1f", pingResult.PacketLoss) // PacketLoss is the percentage of packets lost
		jitter := pingResult.MaxRtt - pingResult.MinRtt          // Jitter is the deviation from true periodicity of a presumably periodic signal

		// Publish to console
		fmt.Println(fmt.Sprintf("--- PING %s (%s) statistics ---", ipAddresses[i], ipAddr))
		// rtts
		for i := range rtts {
			rtt := durationToString(rtts[i])
			fmt.Println(fmt.Sprintf("rtts: icmp_seq=%d time=%v ms", i+1, rtt))
		}
		fmt.Println(fmt.Sprintf("%d packets transmitted, %d packets received, %v%% packet loss, %v Jitter", packetsSent, packetsRecv, packetLoss, jitter))
		fmt.Println(fmt.Sprintf("round-trip min/avg/max/stddev = %v/%v/%v/%v ms", minRtt, avgRtt, maxRtt, stdDevRtt))
		fmt.Println()
		// End publish to console

		// Publish data to MQTT
		var token MQTT.Token
		if mqtt != "" {
			// MQTT
			// Create MQTT Client
			client := MQTT.NewClient(mqttOpts)
			if token = client.Connect(); token.Wait() && token.Error() != nil {
				fmt.Println(token.Error())
				//logger.Println(connectionMQTTLost, mqttAddrAttr)
			}

			// Prepare Topics
			topic := topicPrefix + user + "/" + ipAddr + "/"
			topicUserID := topic + "user_id"
			topicSourceID := topic + "source_id"
			topicSourceIP := topic + "source_ip"
			topicRtts := topic + "rtts"
			topicPacketLoss := topic + "packet_loss"
			topicJitter := topic + "jitter"

			// Publish
			token = client.Publish(topicUserID, byte(qos), false, userID)
			token = client.Publish(topicSourceID, byte(qos), false, sourceID)
			token = client.Publish(topicSourceIP, byte(qos), false, clientIP)
			for j := range rtts {
				rtt := durationToString(rtts[j])
				token = client.Publish(topicRtts, byte(qos), false, rtt)
			}
			token = client.Publish(topicPacketLoss, byte(qos), false, packetLoss)
			token = client.Publish(topicJitter, byte(qos), false, jitter)
			fmt.Println(topicJitter, jitter)
			fmt.Println(fmt.Sprintf("Information was successfully sent to the MQTT topic: %s", topic))
			fmt.Println()
			token.Wait()
			client.Disconnect(250)
		}
		// After Ping Results
		time.Sleep(connectionDelayByHost * time.Second)
	}

}

func main() {
	// How many PC cores to use
	runtime.GOMAXPROCS(maxProcs)

	// Init Error Logger
	f, err := os.OpenFile(logFileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("Could not initialize Logger")
		fmt.Println(err.Error())
		os.Exit(1)
	}
	defer f.Close()
	logger = log.New(f, "", log.LstdFlags)

	// Welcome Message
	fmt.Println(fmt.Sprintf("%s [v%s]", appName, appVersion))
	fmt.Println(welcomeMsg)
	fmt.Println()

	// Get Console Flags
	var ip string   // List of IP addresses (separate by comma if multiple values: host1.com,host2.com)
	var n int       // Number of ICMP Echo Requests to send
	var mqtt string // MQTT Server
	var p string    // MQTT Port
	var user string // User Name & MQTT Login authentication
	var pass string // MQTT Password authentication

	flag.StringVar(&ip, "ip", "", "List of IP addresses (separate by comma if multiple values: host1.com,host2.com)")
	flag.IntVar(&n, "n", defaulPingRequests, "Number of ICMP Echo Requests to send")
	flag.StringVar(&mqtt, "mqtt", "", "MQTT Server")
	flag.StringVar(&p, "p", "1883", "MQTT Port")
	flag.StringVar(&user, "user", "", "User Name & MQTT Login authentication")
	flag.StringVar(&pass, "pass", "", "MQTT Password authentication")
	flag.Parse()

	// Parse Console Flags

	// IP addresses
	var ipAddresses []string
	if ip != "" {
		ipAddresses = strings.Split(ip, ",")
	}

	// Limit Number of ICMP Echo Requests to send
	if n > maxPingRequests {
		n = defaulPingRequests
	}

	// Choosing a place to publish data
	var mqttOpts *MQTT.ClientOptions
	if mqtt != "" {
		// MQTT
		//
		// Generate unique ClientID
		clientID := user + "-" + GenerateSHA1Hash(fmt.Sprintf("%v", time.Now().Format(time.StampNano)))
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
	pingA(mqttOpts, ipAddresses, n, mqtt, p, user, pass)
}
