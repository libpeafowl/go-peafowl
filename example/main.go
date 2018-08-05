package main

import (
	"flag"
	"io"
	"log"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcapgo"
	gopeafowl "github.com/negbie/go-peafowl"
)

var (
	pcapFile = flag.String("rf", "", "PCAP file")
)

type PcapgoHandle struct {
	reader     *pcapgo.Reader
	fileReader io.ReadCloser
}

func NewPcapgoHandle(f string) (*PcapgoHandle, error) {
	fileReader, err := os.Open(f)
	if err != nil {
		return nil, err
	}

	reader, err := pcapgo.NewReader(fileReader)
	if err != nil {
		return nil, err
	}
	return &PcapgoHandle{
		reader:     reader,
		fileReader: fileReader,
	}, nil
}

func (a *PcapgoHandle) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	data, ci, err := a.reader.ReadPacketData()
	return data, ci, err
}

func (a *PcapgoHandle) Close() error {
	return a.fileReader.Close()
}

func main() {
	flag.Parse()
	dpi, err := gopeafowl.NewDPI()
	if err != nil {
		log.Fatal("dpi_init_stateful ERROR")
	}
	defer dpi.Close()

	h, err := NewPcapgoHandle(*pcapFile)
	if err != nil {
		log.Fatal(err)
	}
	defer h.Close()

	for {
		data, ci, err := h.ReadPacketData()

		if err == io.EOF {
			log.Println("-------------------------------------")
			log.Println(dpi.ShowStats())
			log.Println("-------------------------------------")
			log.Fatal("reached end of file")
		} else if err != nil {
			log.Fatal(err)
		}

		proto := dpi.GetProtocol(data, 0, ci.Timestamp, ci.Length, len(data))
		if proto == 8 {
			log.Printf("http packet with %d bytes", len(data))
		}
	}
}
