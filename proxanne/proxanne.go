package main

import (
// 	"bytes"
	"log"
	"log/syslog"
	"net"
 	"net/smtp"
// 	"io/ioutil"
	"errors"
	"smtpd"
	"fmt"
	"flag"
	"github.com/coreos/go-systemd/daemon"
)

var cfg struct {
	listenAddr string
	sysLogging bool 
	spamdAddr  string
	smtpAddr   string
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
		return fmt.Sprintf("Message from <%s> to <%s>, scan result: <%s> %s (%f/%f) [%s]", from, rcpt, isSpam, stat.Message, stat.Score, stat.Threshold, rulz)
}

func mailHandler(origin net.Addr, from string, to []string, data []byte) error {
	cc:=SpamClient{"tcp",cfg.spamdAddr}
	mailout,err:=smtp.Dial(cfg.smtpAddr)
	if err!=nil {
		log.Printf("Message from %s to %s. Cannot connect to SMTP server: %s",from,to,err)
		return errors.New("Cannot connect back to SMTP server: "+err.Error())
	}
	for _,rcpt:= range to {
		// log.Printf("Message from %s to %s, starting scan", from, rcpt)
		res,err:=cc.Report(data,rcpt)
		if err!=nil {
			log.Printf("Message from %s to %s. Cannot evaluate message: %s",from,to,err)
			return errors.New("Cannot process message: "+err.Error())
		}
		log.Printf(mkLogLine(from, rcpt, res))
		err=mailout.Mail(from)
		if err!=nil { log.Printf("From refused"); return errors.New("SMTP refused FROM"); }
		mailout.Rcpt(rcpt)
		if err!=nil { log.Printf("Rcpt refused"); return errors.New("SMTP refused RCPT"); }
		wr,err:=mailout.Data()
		if err!=nil { log.Printf("Data message"); return errors.New("SMTP refused DATA"); }
		wr.Write([]byte(mkSpamStatusLine(res)))
		n:=0
		for n<len(data) {
			n1,err:=wr.Write(data[n:])
			if err!=nil { log.Printf("Data message"); return errors.New("SMTP error writing data") }
			n=n+n1
			}
		wr.Close()
	}
	return nil
}

func init() {
	flag.StringVar(&cfg.listenAddr,"listen","127.0.0.1:2525","address:port to listen on")
	flag.BoolVar(&cfg.sysLogging,"syslog",false,"Enable syslog logging")
	flag.StringVar(&cfg.spamdAddr,"spamd","127.0.0.1:783","spamd address and port")
	flag.StringVar(&cfg.smtpAddr,"smtpd","127.0.0.1:10025","SMTP address and port for reinjection")
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

