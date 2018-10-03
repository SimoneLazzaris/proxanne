# proxanne
SMTP proxy used bind spamassassin with postfix for post-queue spam detection.

I've created this project because I wasn't satisfied with the current options available to interface postfix with spamd 
(spamassassin).

The majority seems to use amavis, which I find too complicated, and uses a different database for user settings than that
used by plain spamassassin/spamd.

So I've assembled a very simple proxy, which accepts messages via SMTP (tipically on a loopback port), sends them to spamd via
a nativa golang tcp client, and then forwards the result via SMTP, usually back to postfix.

The proxy is configured via command line, and has a very few options:
 - the address:port couple used to listen for incoming SMTP connection
 - the address:port couple of the waiting spamd process
 - the address:port couple of the waiting mail process for reinjection

```
Usage of proxanne/proxanne:
  -listen string
        address:port to listen on (default "127.0.0.1:2525")
  -smtpd string
        SMTP address and port for reinjection (default "127.0.0.1:10025")
  -spamd string
        spamd address and port (default "127.0.0.1:783")
  -syslog
        Enable syslog logging
```
