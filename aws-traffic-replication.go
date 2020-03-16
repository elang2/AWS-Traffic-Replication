package main

import (
	"bufio"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/examples/util"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
)


type httpStreamFactory struct{}

// httpStream will handle the actual decoding of http requests.
type httpStream struct {
	net, transport gopacket.Flow
	r              tcpreader.ReaderStream
}

func (h *httpStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	hstream := &httpStream{
		net:       net,
		transport: transport,
		r:         tcpreader.NewReaderStream(),
	}
	go hstream.run()
	return &hstream.r
}
func (h *httpStream) run() {
	buf := bufio.NewReader(&h.r)
	for {
		req, err := http.ReadRequest(buf)
		if err == io.EOF {
			return
		} else if err != nil {
		} else {
			payload, _ := ioutil.ReadAll(req.Body)
			go replayRequestWithPayload(payload, req)
		}
	}
}

func replayRequestWithPayload(payload []byte, httpReq *http.Request) {
	client := &http.Client{}
	payloadAsString := string(payload)
	newreq, _ := http.NewRequest(httpReq.Method, "http://service.staging.hulu.com" + httpReq.RequestURI, strings.NewReader(payloadAsString))
	newreq.Close = true
	// Copy Headers
	for k, v := range httpReq.Header {
		newreq.Header.Add(k, v[0])
	}
	response, err := client.Do(newreq)
	if response != nil {
		fmt.Println(" Response is ", response.StatusCode)
		fmt.Printf("Done with %s to %s \n", httpReq.Method, httpReq.RequestURI)
	}
	if err != nil {
		fmt.Println(" Issue with replaying request %s", err)
	}
}

func main() {
	defer util.Run()()
	handle, err := pcap.OpenLive("eth0", 20001, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	}
	filter := "udp"
	if err := handle.SetBPFFilter(filter); err != nil {
		panic(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	streamFactory := &httpStreamFactory{}
	streamPool := tcpassembly.NewStreamPool(streamFactory)

	for overlayPacket := range packetSource.Packets() {
		vxlanLayer := overlayPacket.Layer(layers.LayerTypeVXLAN)
		if vxlanLayer != nil {
			vxlanPacket, _ := vxlanLayer.(*layers.VXLAN)
			packet := gopacket.NewPacket(vxlanPacket.LayerPayload(), layers.LayerTypeEthernet, gopacket.Default)
			assembler := tcpassembly.NewAssembler(streamPool)
			go process_packet(packet, assembler)
		}
	}
}

func process_packet(packet gopacket.Packet, assembler *tcpassembly.Assembler) {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	tcp, _ := tcpLayer.(*layers.TCP)
	if tcp != nil {
		assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)
	}
}