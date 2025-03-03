package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"net"
	"time"
	"sort"
	"os"
)

const timeout = 60 // Monitor for 60 seconds

// Store the sequence numbers for a particular IP
type ipPacketSequence struct {
	ip        string
	seqNums   []int64
	count     int
	capacity  int
}

// Global packet sequence storage
var packetSequence ipPacketSequence

// Packet callback function to process captured packets
func packetCallback(packet gopacket.Packet) {
	ipLayer := packet.Layer(gopacket.LayerTypeIPv4)
	if ipLayer == nil {
		return
	}

	ipHeader, _ := ipLayer.(*gopacket.layers.IPv4)
	tcpLayer := packet.Layer(gopacket.LayerTypeTCP)
	if tcpLayer == nil {
		return
	}

	tcpHeader, _ := tcpLayer.(*gopacket.layers.TCP)

	srcIP := ipHeader.SrcIP.String()
	dstIP := ipHeader.DstIP.String()
	seqNum := tcpHeader.Seq

	// Check if this is the destination IP we are monitoring
	if dstIP == packetSequence.ip {
		// Resize the sequence number array if necessary
		if packetSequence.count == packetSequence.capacity {
			packetSequence.capacity *= 2
			packetSequence.seqNums = append(packetSequence.seqNums, make([]int64, packetSequence.capacity)...)
		}

		// Store the sequence number
		packetSequence.seqNums[packetSequence.count] = seqNum
		packetSequence.count++

		fmt.Printf("Received packet from %s to %s with sequence number: %d\n", srcIP, dstIP, seqNum)
	}
}

// Detect potential Gray Hole attack by checking for missing packets
func detectGrayHole() {
	fmt.Println("Monitoring traffic for potential Gray Hole Attack...")

	// Wait for a timeout period (e.g., 60 seconds)
	startTime := time.Now()
	for time.Since(startTime).Seconds() < timeout {
		if packetSequence.count > 1 {
			// Sort the sequence numbers to detect missing packets
			sort.Slice(packetSequence.seqNums[:packetSequence.count], func(i, j int) bool {
				return packetSequence.seqNums[i] < packetSequence.seqNums[j]
			})

			// Look for missing packets in the sequence
			for i := 1; i < packetSequence.count; i++ {
				if packetSequence.seqNums[i] != packetSequence.seqNums[i-1]+1 {
					fmt.Printf("Missing packets detected between %d and %d\n", packetSequence.seqNums[i-1], packetSequence.seqNums[i])
					fmt.Println("Potential Gray Hole Attack detected!")
					return
				}
			}
		}
		time.Sleep(1 * time.Second)
	}

	fmt.Printf("No Gray Hole detected within the last %.0f seconds of monitoring.\n", timeout)
}

// Start monitoring the network traffic
func startMonitoring(ipAddress string) {
	// Set up the pcap handle
	handle, err := pcap.OpenLive("eth0", 1600, true, pcap.BlockForever)
	if err != nil {
		fmt.Printf("Error opening device: %v\n", err)
		os.Exit(1)
	}
	defer handle.Close()

	// Set up the packet sequence storage
	packetSequence.seqNums = make([]int64, 10)
	packetSequence.capacity = 10
	packetSequence.count = 0
	packetSequence.ip = ipAddress

	// Start packet capture
	fmt.Println("Starting packet capture...")
	err = handle.SetBPFFilter(fmt.Sprintf("ip host %s", ipAddress))
	if err != nil {
		fmt.Printf("Error setting BPF filter: %v\n", err)
		os.Exit(1)
	}

	// Start packet capture loop
	err = handle.RunPacketSource(packetCallback)
	if err != nil {
		fmt.Printf("Error during packet capture: %v\n", err)
	}

	// After capturing, analyze the traffic for Gray Hole attack
	detectGrayHole()
}

func main() {
	// Get the IP address to monitor
	var ipAddress string
	fmt.Print("Enter the IP address to monitor for Gray Hole Attack:")
	fmt.Scanf("%s", &ipAddress)

	// Start monitoring the network
	startMonitoring(ipAddress)
}
