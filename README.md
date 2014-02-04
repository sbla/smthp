smthp
=====

smtp honeypot

simplest way to use:
- create a jar
- redirect port 25 to port 4444 (or whatever configured)
- launch screen
- java -jar SmtpServer.jar | tee smtp.log


Configure server.properties:
```
smtp.server.name=mail.smtp.tld  (your public Mailname)
smtp.server.banner=ESMTP Postfix (Debian/GNU) (Server Banner)
smtp.server.port=4444 (local port to open)
smtp.server.backlog=0 (Serversocket backlog)
#smtp.server.bindaddress= (address to bind)
smtp.threadpool.size=100 (Threadpool size/how many concurrent connections can be accepted)
```
