package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/Sirupsen/logrus"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/jessevdk/go-flags"
	"github.com/yyd01245/rtpParse"
)

var opts struct {
	InFile  string `short:"i" long:"infile" description:"Input file path"`
	OutFile string `short:"o" long:"outfile" default:"./output.264" description:"output file path"`
	Filter  string `short:"f" long:"filter" description:"filter data"`
	Log     string `short:"l" long:"log" description:"the log file to tail -f"`
}

const (
	PLAYLOAD_FU_A   = 28
	PLAYLOAD_STAP_A = 24
)

const (
	PLAYLOAD_VIDEO = 107
	PLAYLOAD_AUDIO = 111
)

var log *logrus.Logger

func init() {
	log = logrus.New()
	log.Level = logrus.InfoLevel
	f := new(logrus.TextFormatter)
	f.TimestampFormat = "2006-01-02 15:04:05"
	f.FullTimestamp = true
	log.Formatter = f
}

var h264StartCode = []uint8{0x0, 0x0, 0x0, 0x01, 0x0}

var ADTS = []uint8{0xFF, 0xF1, 0x00, 0x00, 0x00, 0x00, 0xFC}

func parsePcapFile(inFilePath string, outFilePath string, filterData string) (ret int, err error) {
	//descr := []byte("This is a test description.")
	// read file
	fi, err := pcap.OpenOffline(inFilePath)
	ret = -1
	if err != nil {
		err := fmt.Errorf("open file error")
		return ret, err
	}
	defer fi.Close()
	ret = -2
	var filter string = filterData
	err = fi.SetBPFFilter(filter)
	if err != nil {
		err := fmt.Errorf("set filter file error")
		return ret, err
	}
	out, err := os.Create(outFilePath)
	if err != nil {
		err := fmt.Errorf("creat %s file error", outFilePath)
		return ret, err
	}
	defer out.Close()
	log.Printf("open file success \n")

	flag := true
	packetSource := gopacket.NewPacketSource(fi, fi.LinkType())
	for packet := range packetSource.Packets() {
		if flag {
			log.Println("%x", packet.ApplicationLayer().Payload())
			flag = false
		}
		var data []uint8 = packet.ApplicationLayer().Payload()
		// need offset 2 packet last 2 bytes
		var offset int = 2
		var packetLen = len(data) - offset
		log.Println("packet len : ", packetLen)
		upyHead, _ := rtpParse.GetPrivateAHead(data[offset:])
		log.Println("private head: ", *upyHead)
		offset += int(upyHead.HeaderLen)
		rtpHead, _ := rtpParse.GetRtpHead(data[offset:])
		log.Println("rtp head: ", *rtpHead)
		offset += int(rtpHead.HeaderLen)
		if rtpHead.Typ == PLAYLOAD_VIDEO {
			naluHead, _ := rtpParse.GetNALUHead(data[offset:])
			log.Println("nalu head: ", *naluHead)
			offset += int(naluHead.HeaderLen)
			if naluHead.TYPE == PLAYLOAD_FU_A {
				fragunitHead, _ := rtpParse.GetFUAHead(data[offset:])
				offset += int(fragunitHead.HeaderLen)
				log.Println("fu-a head: ", *fragunitHead)
				if fragunitHead.S == 1 {
					// started
					h264StartCode[4] = (h264StartCode[4]>>5 | 0x03) << 5
					h264StartCode[4] = h264StartCode[4] | fragunitHead.TYPE
					out.Write(h264StartCode)
					out.Sync()
				} else if fragunitHead.E == 1 {
					// end
				} else {
					// internal data
				}
				pLen := packetLen - offset
				log.Println("write fu-a len ", pLen)
				out.Write(data[offset:])
				out.Sync()
			} else if naluHead.TYPE == PLAYLOAD_STAP_A {
				lastLen := packetLen - offset
				for ; lastLen > 2; lastLen = packetLen - offset {
					stapHead, _ := rtpParse.GetStapAHead(data[offset:])
					log.Println("stap-a head: ", *stapHead)
					offset += int(stapHead.HeaderLen)
					log.Println("stap-a nalsize ", stapHead.NaluSize)
					out.Write(h264StartCode[:4])
					//	end :=
					out.Write(data[offset : offset+int(stapHead.NaluSize)])
					out.Sync()
					log.Println("write stap-a len ", stapHead.NaluSize)
					offset += int(stapHead.NaluSize)

				}
			}
		} else if rtpHead.Typ == PLAYLOAD_AUDIO {
			var audioSamprate int = 44100
			var audioChannel int = 2
			var audioBit int = 16
			switch audioSamprate {
			case 16000:
				ADTS[2] = 0x60
			case 32000:
				ADTS[2] = 0x54
			case 44100:
				ADTS[2] = 0x50
			case 48000:
				ADTS[2] = 0x4C
			case 96000:
				ADTS[2] = 0x40
			default:
				break
			}
			if audioChannel == 2 {
				ADTS[3] = 0x80
			} else {
				ADTS[3] = 0x40
			}
			recvLen := packetLen - offset
			log.Println(audioBit, recvLen)
			/*
			   ADTS[3] = (audioChannel==2)?0x80:0x40;

			   int len = recvLen - 16 + 7;
			   len <<= 5;//8bit * 2 - 11 = 5(headerSize 11bit)
			   len |= 0x1F;//5 bit    1
			   ADTS[4] = len>>8;
			   ADTS[5] = len & 0xFF;
			   *pBufOut = (char*)bufIn+16-7;
			   memcpy(*pBufOut, ADTS, sizeof(ADTS));
			   *pOutLen = recvLen - 16 + 7;

			   unsigned char* bufTmp = (unsigned char*)bufIn;
			   bool bFinishFrame = false;
			   if (bufTmp[1] & 0x80)
			   {
			       //DebugTrace::D("Marker");
			       bFinishFrame = true;
			   }
			   else
			   {
			       bFinishFrame = false;
			   }
			*/
		}

	}
	ret = 0
	return ret, nil
}

func main() {
	_, err := flags.Parse(&opts)
	if err != nil {
		if !strings.Contains(err.Error(), "Usage") {
			log.Fatalf("error: %v", err)
		} else {
			return
		}
	}
	if opts.InFile == "" || opts.Filter == "" {
		log.Println("error no input file and filter")
		return
	}
	_, err = parsePcapFile(opts.InFile, opts.OutFile, opts.Filter)
	if err != nil {
		log.Println("error parse pcap file ")
	}

}
