package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	log "github.com/sirupsen/logrus"
)

type FlowKey struct {
	Src gopacket.Endpoint
	Dst gopacket.Endpoint
}

type FlowStat struct {
	Size  uint64
	Count uint
}

type Bucket struct {
	FastHash uint64
	Map      map[FlowKey]*FlowStat
}

func (b *Bucket) ProcessStat(src, dst gopacket.Endpoint, length int) {
	key := FlowKey{
		Src: src,
		Dst: dst,
	}
	var stat *FlowStat
	var ok bool
	if stat, ok = b.Map[key]; !ok {
		stat = &FlowStat{
			Size:  0,
			Count: 0,
		}
	}
	stat.Size += uint64(length)
	stat.Count += 1
	b.Map[key] = stat
}

func main() {
	var err error
	flag.Parse()
	pcapFile := flag.Arg(0)
	if pcapFile == "" {
		log.Warn("please provide pcap-file to analyze")
		return
	}
	if _, err = os.Stat(pcapFile); err != nil {
		log.WithError(err).WithField("pcap-file", pcapFile).Error("error accessing pcap-file")
		return
	}
	var handle *pcap.Handle
	if handle, err = pcap.OpenOffline(pcapFile); err != nil {
		log.WithError(err).WithField("pcap-file", pcapFile).Error("error opening pcap-file")
		return
	}
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	count := 0
	stats := make(map[uint64]*Bucket, 0)
	var bucket *Bucket
	var key FlowKey
	var stat *FlowStat
	var ok bool
	for packet := range packetSource.Packets() {
		if nl := packet.NetworkLayer(); nl != nil {
			count += 1
			f := nl.NetworkFlow()
			src, dst := f.Endpoints()
			packetLength := packet.Metadata().Length
			h := f.FastHash()
			bucket, ok = stats[h]
			if !ok {
				bucket = &Bucket{
					FastHash: h,
					Map:      make(map[FlowKey]*FlowStat, 0),
				}
				stats[h] = bucket
			}
			bucket.ProcessStat(src, dst, packetLength)
		}
	}
	for _, bucket = range stats {
		for key, stat = range bucket.Map {
			fmt.Printf("%s -> %s total %d bytes sent in %d packets\n", key.Src, key.Dst, stat.Size, stat.Count)
		}
	}
}
