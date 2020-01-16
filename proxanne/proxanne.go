package main

import (
	"bytes"
 	"io"
	"log"
	"log/syslog"
	"net"
 	"net/smtp"
	"strings"
 	"math/rand"
	"errors"
	"smtpd"
	"fmt"
	"flag"
	"regexp"
	"github.com/coreos/go-systemd/daemon"
)

var cfg struct {
	listenAddr string
	sysLogging bool 
	spamdAddr  string
	smtpAddr   string
	saSize     int
	cutOff     int
}

type HeaderInfo struct {
	messageid	string
	subject		string 
}

func mkSpamStatusLine(stat Result) string {
	isSpam:="No"
	if (stat.Spam) {isSpam="Yes"}
	ret:=fmt.Sprintf("X-Spam-Status: %s, score=%f, required=%f tests=",isSpam,stat.Score, stat.Threshold)
	for i,hh:=range stat.Details {
		if i>0 {ret=ret+","}
		if (i%6)==0 {ret=ret+"\n    "}
		ret=ret+hh.RuleName
	}
	ret=ret+"\n"
	ret=ret+fmt.Sprintf("X-Spam-Flag: %s\n",strings.ToUpper(isSpam))
	return ret
}

func mkLogLine(from string, rcpt string, stat Result) string {
		rulz:=""
		for i,hh:=range stat.Details {
			if i>0 {rulz=rulz+" "}
			rulz=rulz+fmt.Sprintf("%s(%s)",hh.RuleName,hh.Points)
		}
		isSpam:="GOOD"
		if stat.Spam { isSpam="SPAM"; }
		return fmt.Sprintf("Message from <%s> to <%s>, %%s Scan result: <%s> %s (%.2f/%.2f) [%s]", from, rcpt, isSpam, stat.Message, stat.Score, stat.Threshold, rulz)
}


func saConnect() (SpamClient, error) {
	saList:=strings.Split(cfg.spamdAddr,",")
	// shuffle the array
	for i := range saList {
		j := rand.Intn(i + 1)
		saList[i], saList[j] = saList[j], saList[i]
	}
	for _,ss:=range saList {
		cc:=SpamClient{"tcp",ss}
		if cc.Ping()==nil {
			return cc,nil
		log.Printf("spamd server %s unreachable",ss)
		}
	}
	return SpamClient{"",""},errors.New("Cannot connect to spamd")
}

func xsend(data[]byte, wr io.WriteCloser) error {
	n:=0
	siz:=len(data)
	for n<siz {
		n1,err:=wr.Write(data[n:])
		if err!=nil { return errors.New("SMTP error writing data") }
		n=n+n1
	}
	return nil
}

func xtractHeaders(data[]byte) (int, [][]byte) {
	hstop:=bytes.Index(data, []byte{'\r','\n','\r','\n'} )
	if hstop==-1 {
		return -1,[][]byte{}
	}
	headers:=bytes.Split(data[:hstop+2], []byte{'\r','\n'})
	h2:=make([][]byte,len(headers))
	i2:=0
	for idx,hed:=range headers {
		if idx==0 || (!bytes.HasPrefix(hed,[]byte{' '}) && !bytes.HasPrefix(hed,[]byte{'\t'})) {
			h2[i2]=hed
			i2++
			continue
		}
		h2[i2-1]=append(h2[i2-1], []byte{'\r','\n'}...)
		h2[i2-1]=append(h2[i2-1], hed...)
	}
	return hstop+2,h2
}

func removeHeader(headers [][]byte, rmv string) [][]byte {
	rm2:=[]byte(strings.ToLower(rmv))
	for i:=0; i<len(headers); i++ {
		if bytes.HasPrefix(bytes.ToLower(headers[i]),rm2) {
			return append(headers[:i],headers[i+1:]...)
		}
	}
	return headers
}

func skipHeader(h []byte) bool {
	if bytes.HasPrefix(h,[]byte("X-Spam-Status")) { return true }
	if bytes.HasPrefix(h,[]byte("X-Spam-Flag")) { return true }
	if bytes.HasPrefix(h,[]byte("X-EsetResult")) { return true }
	return false
}

var rx=regexp.MustCompile("^([a-zA-Z0-9-]+)\\s*:\\s*(.*)$")
func parseHeader(h []byte, hed *HeaderInfo) {
// 	fmt.Printf("parsing header [%s]\n",string(h))
	if rx.Match(h) {
// 		fmt.Printf("match\n")
		mx:=rx.FindSubmatch(h)
		if len(mx)<3 { return }
// 		fmt.Printf("%s -> %s\n",string(mx[1]),string(mx[2]))
		switch strings.ToLower(string(mx[1])) {
			case "message-id":
				// fmt.Printf("Message-ID: %s",string(mx[2]))
				hed.messageid=string(mx[2])
			case "subject":
				// fmt.Printf("Subject: %s",string(mx[2]))
				hed.subject=string(mx[2])
		}
	}
}


func mailHandler(origin net.Addr, from string, to []string, data []byte) error {
	cc,err:=saConnect()
	if err!=nil {
		log.Printf("Message from %s to %s. Cannot connect to spamd",from,to,err)
		return err
	}
	mailout,err:=smtp.Dial(cfg.smtpAddr)
	if err!=nil {
		log.Printf("Message from %s to %s. Cannot connect to SMTP server: %s",from,to,err)
		return errors.New("Cannot connect back to SMTP server: "+err.Error())
	}
	for _,rcpt:= range to {
		var res Result 
		var statusLine string
		var logline string
		var wr io.WriteCloser
		drop:=false
		hed:=HeaderInfo{"?","?"}
		if len(data)<cfg.saSize {
			res,err=cc.Report(data,rcpt)
			if err!=nil {
				log.Printf("Message from %s to %s. Cannot evaluate message: %s",from,to,err)
				return errors.New("Cannot process message: "+err.Error())
			}
			logline=mkLogLine(from, rcpt, res)
			if res.Spam && res.Score>res.Threshold+float64(cfg.cutOff) {
				logline=logline+" Message dropped"
				drop=true
			}
			statusLine=mkSpamStatusLine(res)
		} else {
			logline=fmt.Sprintf("Message from %s to %s. %%s Not performing scan, message too big",from,to)
			statusLine="X-Spam-Status: No, score=?, required=? (not scanned, too big)\n"
		}
		if !drop {
			err=mailout.Mail(from)
			if err!=nil { log.Printf("From refused"); return errors.New("SMTP refused FROM"); }
			mailout.Rcpt(rcpt)
			if err!=nil { log.Printf("Rcpt refused"); return errors.New("SMTP refused RCPT"); }
			wr,err=mailout.Data()
			if err!=nil { log.Printf("Data message"); return errors.New("SMTP refused DATA"); }
			
			if err=xsend([]byte(statusLine),wr); err!=nil { log.Printf("Data message"); return err }
			}
		hlen,h2:=xtractHeaders(data)
		for _,h:=range(h2) {
			if len(h)==0 { break }
			if skipHeader(h) { continue }
			parseHeader(h,&hed)
			if drop { continue }
			xsend(h,wr)
			xsend([]byte {'\r','\n'},wr)
		}
		if !drop {
			if err=xsend(data[hlen:],wr); err!=nil {log.Printf("Data message"); return err }
		}
		logline2:=fmt.Sprintf("ID %s, Subject \"%s\".",hed.messageid, hed.subject)
		log.Printf(fmt.Sprintf(logline,logline2))
		if !drop { wr.Close() }
	}
	_=mailout.Quit()
	return nil
}

func init() {
	flag.StringVar(&cfg.listenAddr,"listen","127.0.0.1:2525","address:port to listen on")
	flag.BoolVar(&cfg.sysLogging,"syslog",false,"Enable syslog logging")
	flag.StringVar(&cfg.spamdAddr,"spamd","127.0.0.1:783","spamd address and port")
	flag.StringVar(&cfg.smtpAddr,"smtpd","127.0.0.1:10025","SMTP address and port for reinjection")
	flag.IntVar(&cfg.saSize,"size",524288,"Size threshold in bytes, bigger message will go unscanned")
	flag.IntVar(&cfg.cutOff,"cutoff",10,"Cutoff threshold, will silently discard messages if score>(threshold+cutoff)")
}

func main() {
	
	flag.Parse()
	if (cfg.sysLogging) {
		logwriter, e := syslog.New(syslog.LOG_NOTICE|syslog.LOG_MAIL, "proxanne")
		if e == nil {
			log.SetOutput(logwriter)
			log.SetFlags(0)
			}
		}
	log.Printf("Proxanne starting on %s, spamd: %s smtp %s", cfg.listenAddr, cfg.spamdAddr, cfg.smtpAddr)
	daemon.SdNotify(false, "READY=1")
	smtpd.ListenAndServe(cfg.listenAddr, mailHandler, "Proxanne", "")
}

