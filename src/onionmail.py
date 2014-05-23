#!/usr/bin/python

import os
import socket
import string
import sys
import subprocess
import shutil
import time
import re
import socks
import tty

conf_home="/home/amnesia"
conf_base=conf_home+"/.claws-mail"
conf_certpath=conf_base+"/certs"
conf_accountrc=conf_base+"/accountrc"
conf_maildir=conf_base+"/profiles"
conf_gpg="gpg"
conf_infofile=conf_home+"/onionmail-info-account"
conf_tarprofile="profile.tar.gz"
conf_tarmail="maildir.tar.gz"
conf_clawsmail="/usr/bin/claws-mail"
conf_mkpgp=1
conf_torport=9050
conf_torip="127.0.0.1"
conf_torrc="/etc/tor/torrc"
conf_saveinfo=1
conf_list="onionmail.lst"

stat=1
ret="NOP"
USER=""
PEMCRT=""

DEFAULT_CONFIG="""
[Account: __number__]
account_name=__onionmail__
is_default=__is_default__
name=__username__
address=__onionmail__
organization=__nick__
protocol=0
receive_server=__onion__
smtp_server=__onion__
nntp_server=
local_mbox=/var/mail
use_mail_command=0
mail_command=/usr/sbin/sendmail -t -i
use_nntp_auth=0
use_nntp_auth_onconnect=0
user_id=__username__
password=__pop3password__
use_apop_auth=0
remove_mail=1
message_leave_time=7
message_leave_hour=0
enable_size_limit=0
size_limit=1024
filter_on_receive=1
filterhook_on_receive=1
imap_auth_method=0
receive_at_get_all=1
max_news_articles=300
inbox=__inbox__
local_inbox=__inbox__
imap_directory=
imap_subsonly=1
low_bandwidth=0
generate_msgid=1
generate_xmailer=1
add_custom_header=0
msgid_with_addr=0
use_smtp_auth=1
smtp_auth_method=16
smtp_user_id=__username__
smtp_password=__smtppassword__
pop_before_smtp=0
pop_before_smtp_timeout=5
signature_type=0
signature_path=
auto_signature=0
signature_separator=-- 
set_autocc=0
auto_cc=
set_autobcc=0
auto_bcc=
set_autoreplyto=0
auto_replyto=
enable_default_dictionary=0
default_dictionary=de
enable_default_alt_dictionary=0
default_alt_dictionary=de
compose_with_format=0
compose_subject_format=
compose_body_format=
reply_with_format=0
reply_quotemark=
reply_body_format=
forward_with_format=0
forward_quotemark=
forward_body_format=
default_privacy_system=
default_encrypt=0
default_encrypt_reply=1
default_sign=0
default_sign_reply=0
save_clear_text=0
encrypt_to_self=0
privacy_prefs=gpg=REVGQVVMVA==
ssl_pop=2
ssl_imap=0
ssl_nntp=0
ssl_smtp=2
use_nonblocking_ssl=1
in_ssl_client_cert_file=
in_ssl_client_cert_pass=!
out_ssl_client_cert_file=
out_ssl_client_cert_pass=!
set_smtpport=1
smtp_port=25
set_popport=1
pop_port=110
set_imapport=0
imap_port=143
set_nntpport=0
nntp_port=119
set_domain=0
domain=
gnutls_set_priority=0
gnutls_priority=
mark_crosspost_read=0
crosspost_color=0
set_sent_folder=0
sent_folder=
set_queue_folder=0
queue_folder=
set_draft_folder=0
draft_folder=
set_trash_folder=0
trash_folder=
imap_use_trash=1
"""

Col = {}
Col["0"] = "\033[0m"    
Col["red"] = "\033[0;31m"         
Col["green"] = "\033[0;32m"       
Col["yellow"] = "\033[0;33m"     
Col["blue"] = "\033[0;34m"       
Col["purple"] = "\033[0;35m"     
Col["cyan"] = "\033[0;36m"       
Col["white"] = "\033[0;37m"       
Col["ored"] = "\033[41m"     
Col["ogreen"] = "\033[42m"     
Col["oyellow"] = "\033[43m"     
Col["oblue"] = "\033[44m"       
Col["opurple"] = "\033[45m"    
Col["ocyan"] = "\033[46m"      

class PException(Exception): pass

def inittheclaws():
    if os.path.exists(conf_base)==False:
        print Col["cyan"]+"Building the Claws-Mail's profile"+Col["0"]
        os.makedirs(conf_base)
        p = subprocess.Popen("tar -xf "+conf_tarprofile+" -C "+conf_base + " > /dev/null", shell=True)
        ret = p.wait()
        if ret==0:
            print "\t" + Col["blue"]+"Done!!!"+Col["0"]
        else:
            print "\t" + Col["erd"]+"Error "+str(ret)+Col["0"]
            sys.exit(1)

def parsetor():
    "Parse torrc and get the tor SOCKS proxy"
    global conf_torport
    global conf_torip
    
    fh = open(conf_torrc,"r")
    li = fh.read()
    fh.close()
    li = string.replace(li,"\r\n","\n")
    li = string.split(li,"\n")
    fh=""
    for index in range(len(li)):
        ln = li[index]
        tok = string.split(ln,"#",2)
        ln=tok[0]
        fh = fh + string.strip(ln) + "\n"
    
    fh = string.lower(fh)
    fh1 = re.search( r'^\s*socksport\s+(?P<port>[0-9]{1,5})' , fh)
    if fh1:
        fh1 = fh1.groupdict()
        conf_torport=fh1["port"]
    
    fh1 = re.search( r'^\s*sockslistenaddress\+(?P<ip>[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})' , fh)
    if fh1:
        fh1 = fh1.groupdict()
        fh1 = fh1["ip"]
        ip = string.split(fh1,".")
        if ip[3]!="0" and ip[0]!="0":
            conf_torip=fh1

def creategpgkey(mail,name,bits,passwd):
    "Generates a PGP key via gpg"
    cmd = "--batch --gen-key --yes"
    sti ="Key-Type: RSA\n"
    sti = sti + "Key-Length: "+bits+"\n"
    sti = sti + "Passphrase: "+passwd+"\n"
    sti = sti + "Expire-Date: 0\n"
    sti = sti + "Subkey-Length: "+bits+"\n"
    sti = sti + "Subkey-Type: RSA\n"
    sti = sti + "Name-Real: "+name+"\n"
    sti = sti + "Name-Email: "+mail+"\n"
    sti = sti + "%commit\n"
    sti = sti + "%save\n"
    sti = sti + "%echo done\n"
    sti = sti + "\031\n\n"

    p = subprocess.Popen(conf_gpg+" "+cmd,shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE)
    p.stdin.write(sti)
    return p.wait()
    
def perro(st):
    "Do an error on stat=0 (this is not a spanish dog!)"
    if (stat==0):
        print Col["red"] + st + Col["0"]
        sok.close()
        raise PException("PERRO")

def writedata(dta):
    "Sends multiline data in POP3 protocol"
    dta=string.strip(dta)
    if (dta!=""):
        dta=string.replace(dta,"\r\n","\n")
        dta=string.replace(dta,"\r","")
        dta=string.split(dta,"\n")
        for index in range(len(dta)):
            send(dta)
            
    send(".")
            
def rdln():
    "Read a line from raw socket"
    i = 0
    li=""
    while(i<80):
        ch = sok.recv(1)
        if (ch=="\r"):
            break
    
        if (ch!="\n"):
            li = li + ch
        
        i = i +1
    return li

def rdcmd():
    "Read a cmd result"
    global stat
    global ret
    
    data = rdln()
    tok = string.split(data," ")
    if (len(tok)<2):
        ret=""
    else:
        ret=tok[1]

    if tok[0]=="+OK":
        stat=1
    else:
        stat=0
    return tok

def rdcmdm():
    "This read a multi line POP3 command return"
    st = rdcmd()
    if (ret==0):
        return ""
    i=0
    rs=""
    while(i<4000):
        i = i+1
        li = rdln()
        if li == ".":
            break
        rs = rs+li+"\n"
    return rs

def send(cmd):
    "Send a POP3 command"
    st=cmd+"\r\n"
    sok.sendall(st)

def parseheaders(dta):
    "Parse a string as headers"
    dta=string.strip(dta)
    dta=string.replace(dta,"\r\n","\n")
    dta=string.split(dta,"\n")
    hldr = {}
    for index in range(len(dta)):
        if string.find(dta[index],":") != -1:
            tok = string.split(dta[index],":",2)
            tok[0] = string.strip(tok[0])
            tok[1] = string.strip(tok[1])
            tok[0] = string.lower(tok[0])
            hldr[tok[0]]=tok[1]
    
    return hldr

def replacer(orig,hldr):
    "Replace __key__ from hldr"
    rs=orig
    for key in hldr:
        k1 = "__"+key+"__"
        rs=string.replace(rs,k1,hldr[key])
    return rs

def ferro(st):
    "Force an error (This is not an italian metal!)"
    if st=="":
        st="Invalid USER data from server"
    print "\n"+Col["ored"]+st+Col["0"]
    raise PException("FERRO")

def checkuser():
    "Test user data"
    global USER
    ma = re.match(r'^[a-z0-9]{16}\.onion$',USER["onion"])
    if ma==False:
        ferro("")
    
    ma = re.match(r'^[a-z0-9\_\-\.]{1,40}\@[a-z0-9]{16}\.onion$',USER["onionmail"])
    if ma==False:
        ferro("")
    
    ma = re.match(r'^[a-z0-9\-\_\.]{1,40}$',USER["username"])
    if ma==False:
        ferro("")

def configuser():
    "Configure claws-mail"
    global USER
    USER["inbox"]=conf_maildir+"/201"
    USER["number"]="201"
    USER["is_default"]="0"

    conf = open(conf_accountrc,"r")
    dt = conf.read()
    conf.close()

    for index in range(1,200):
        if string.find(dt,"[Account: " + str(index)+"]")==-1:
            USER["number"] = str(index)
            break

    USER["inbox"]=conf_maildir + "/account"+USER["number"]

    ua = DEFAULT_CONFIG
    ua = replacer(ua,USER)
    dt = dt + ua
    ua=""

    conf = open(conf_accountrc,"w")
    conf.write(dt)
    conf.close()
    
    os.makedirs(USER["inbox"])
    p = subprocess.Popen("tar -xf "+conf_tarmail+" -C "+USER["inbox"] +" > /dev/null", shell=True)
    ret = p.wait()
    if ret!=0:
        ferro("Error "+str(ret))    

def configssl(outp):
    "Config SSL certificate"
    global PEMCRT
    temp="/tmp/onionsetup"+str(time.time())+".tmp"
    fi = open(temp,"w")
    fi.write(PEMCRT)
    fi.close()
    p = subprocess.Popen("openssl x509 -in "+temp+" -inform PEM -out "+temp+".out -outform DER", shell=True)
    ret = p.wait()
    os.remove(temp)
    temp=temp+".out"
    if os.path.exists(conf_certpath)==False:
        os.makedirs(conf_certpath)

    shutil.copyfile(temp,conf_certpath+"/"+outp+".25.cert")
    shutil.move(temp,conf_certpath+"/"+outp+".110.cert")
    return ret

def onionmail(hiddenserv):
	global stat
	global ret
	global sok
	global USER
	global PEMCRT
	
	print Col["purple"] + "Connecting to hidden service '"+Col["cyan"]+hiddenserv+Col["purple"]+"' ..."+Col["0"]
	try:
		socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5,"127.0.0.1",9050,True)
		sok = socks.socksocket()
		sok.connect((hiddenserv,110))
	except IOError:
		print Col["ored"]+"\tError: Can't connect to this hidden service!"+Col["0"]
		raise

	print "\t"+Col["blue"]+"Connected!!!"+Col["0"]

	rs = rdcmd()
	perro("Error on POP3 server")

	send("CAPA")
	rs = rdcmdm()
	perro("Error ip POP3 session")

	if (string.find(rs,"\nRQUS\n") == -1):
	    send("QUIT")
	    rs = rdcmd()
	    sok.close()
	    print Col["ored"]+"This server doesn't support RQUS"+Col["0"]
	    raise PException("PERRO")

	print Col["cyan"]+"New user request"+Col["0"]    
	send("RQUS");
	while(1):
	    rs=rdcmdm()
	    if (ret!="CAPTCHA"):
		perro("Too many error")
		break

	    print rs
	    print Col["purple"] + "Enter CAPTCHA:"+Col["0"]
	    cp = sys.stdin.readline()
	    cp = string.strip(cp)
	    send(cp)

	print Col["purple"]+"Enter voucher code or empty line:"+Col["0"]
	cp = sys.stdin.readline()
	cp = string.strip(cp)
	send(cp)
	rs=rdcmd()
	perro("Operation not permitted on this server")

	while(1):
	    print Col["purple"]+"Enter Username:"+Col["0"]
	    cp = sys.stdin.readline()
	    cp = string.strip(cp)
	    send(cp)
	    rs=rdcmd()
	    if (ret!="USERNAME"):
		perro("Too many error")
		break

	print Col["cyan"]+"Subscribing user, please wait..."+Col["0"]
	writedata("")    
	USER=rdcmdm()
	perro("User subscription error")
	print "\t"+Col["purple"]+"Done!!!"+Col["0"]

	print Col["cyan"]+"Configuring Claws-Mail ..."

	USER=parseheaders(USER)
	checkuser()
	configuser()

	send("PEM")
	PEMCRT=rdcmdm()
	sok.close()

	cp = configssl(USER["onion"])
	if cp!=0:
	    print Col["ored"] + "Error on SSL configuration"+Col["0"]
	    print Col["red"] + "Verify the SSL certificate manually"+Col["0"]
	    print "\t"+Col["blue"]+"SHA1: "+Col["yellow"]+USER["sha1"]+Col["0"]
	    
	print "\t"+Col["purple"]+"Done!!!"+Col["0"]

	if conf_mkpgp!=0:
	    print Col["cyan"]+"Creating a new PGP key"+Col["0"]
	    os.system("stty -echo")
	    
	    while(1):
		print Col["purple"]+"Enter the passphrase:"+Col["0"]
		pha1 = sys.stdin.readline()
		pha1 = string.strip(pha1)
		sys.stdout.write(Col["yellow"])
		for cp in xrange(len(pha1)):
		    sys.stdout.write("*")
		
		print Col["0"]
		print Col["purple"]+"Enter the passphrase again:"+Col["0"]
		pha2 = sys.stdin.readline()
		pha2 = string.strip(pha2)
		sys.stdout.write(Col["yellow"])
		for cp in xrange(len(pha2)):
		    sys.stdout.write("*")
		
		print Col["0"]
		if pha1==pha2:
		    break
		
		print Col["ored"]+"ERROR!"+Col["0"]
		print Col["red"]+"Retry"+Col["0"]

	    os.system("stty echo")

	    while(1):
		print Col["purple"]+"Enter your name:"+Col["0"]
		pha2 = sys.stdin.readline()
		pha2 = string.strip(pha2)
		if len(pha2)>8:
		    break
		
		print Col["red"]+"Too short! Min. = 8 char."+Col["0"]
	
	if conf_saveinfo==1:
		inf=""
		for key in USER:
		    inf = inf + key + " =\t" + USER[key] + "\n"

		conf=open(conf_infofile+USER["number"]+".txt","w")
		conf.write(inf)
		conf.close()

	if conf_mkpgp!=0:
	    print Col["cyan"]+"I'm creating a new PGP key (8192 bits).\n\tWait a few minutes...\n\tThe processing is very complex."+Col["0"]
	    ret = creategpgkey(USER["onionmail"],pha2,"8192",pha1)
	    print "\t"+str(ret)+" "+Col["blue"]+"Done!!!"+Col["0"]
	    pha2=""
	    pha1=""

	print Col["cyan"]+"Account "+Col["green"]+USER["username"]+Col["cyan"]+" created successfully"+Col["0"]
	#print Col["cyan"]+"Press return to start claws-mail"+Col["0"]
	#cp = sys.stdin.readline()
	#os.spawnl(os.P_NOWAIT, conf_clawsmail)

def adj(st,sz):
	if len(st)>sz:
		st=st[0:sz]
	return string.ljust(st,sz)+" "

def serverlist():
	fd = open(conf_list,"r")
	conf = fd.read()
	fd.close()
	conf = string.strip(conf)
	conf = string.split(conf,"\n")
	lst=[]
	for index in range(len(conf)):
		tok = string.split(conf[index],",")
		if len(tok)==4:
			lst.append({"nick":tok[0] , "onion":tok[1], "flg":tok[2],"per":int(tok[3])})

	print "\033[2J\033[0;0H"+Col["purple"]+"Select an OnionMail server:"+Col["0"]

	for index in range(len(lst)):
		cur = lst[index]
		ava = "?"
		if cur["per"]==0:
			ava=Col["red"] + "NOT AVAIL."

		if cur["per"]==0 and cur["flg"]=="V":
			ava=Col["yellow"] + "VOUCHER"

		if cur["per"]>1 and cur["per"]<25:
			ava=Col["yellow"] + str(cur["per"])
	
		if cur["per"]>24 and cur["per"]<51:
			ava=str(cur["per"])
	
		if cur["per"]>50:
			ava=Col["green"] + str(cur["per"])

		print "  "+Col["purple"] + "(" +str(index+1) + ") "+Col["cyan"]+ adj(cur["nick"],11) + Col["blue"] + adj(cur["onion"],22) + ava + Col["0"]

	hserv=""

	while(1):
		print Col["cyan"]+"> "+Col["0"],
		pha2 = sys.stdin.readline()
		pha2 = string.strip(pha2)
		try:
			pha2=int(pha2+"")
			if pha2>0 and pha2<=len(lst):
				pha2=pha2-1
				hserv=lst[pha2]
				return hserv;

		except NameError:
			print "bo"	
			pha2=0

#
################ START ########################
#

if os.path.isfile(conf_tarprofile)==False or os.path.isfile(conf_tarmail)==False or os.path.isfile(conf_list)==False:
    ferro("There is a lack of important files. Maybe you lost some part of the program.")

try:
	parsetor()
	inittheclaws()
	while(1):
		srv = serverlist()
		try:
			print "\033[2J\033[0;0H"+Col["cyan"]+"Connecting to "+Col["green"]+srv["nick"]+Col["0"]+"\n"
			onionmail(srv["onion"])
			break

		except PException:
			print Col["red"] + "Error occurred on "+Col["yellow"]+srv["nick"]+Col["red"]+" server"
			print Col["purple"] + "Press return to try another server."+Col["0"]
			pha2 = sys.stdin.readline()

		except:
			print Col["red"] + "Error occurred in application"
			print Col["purple"] + "Press return to try another server."+Col["0"]
			pha2 = sys.stdin.readline()

except:
	print Col["ored"] + "Application fatal error!"+Col["0"]
