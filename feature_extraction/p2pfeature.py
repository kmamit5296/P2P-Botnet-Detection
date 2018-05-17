import subprocess,re,os
import pyshark,ipaddress,re,thread,threading,time
import binascii
from pcapfile import savefile
from pcapfile.protocols.linklayer import ethernet
from pcapfile.protocols.network import ip

par=[]

class To_ip_data:
    def __init__(self,d_ip,s_port,d_port,prot):
        self.dst_ip=ipaddress.IPv4Address(unicode(d_ip))
        self.s_port=s_port
        self.d_port=d_port    
        self.protocol=prot
        self.num_pck=1
    def __eq__(self, other): 
        if self.dst_ip == other.dst_ip and self.s_port == other.s_port and  self.d_port == other.d_port:
            return True
        else: 
            return False
    def __repr__(self):
        return "["+str(self.dst_ip)+" "+str(self.s_port)+" "+str(self.d_port)+" "+str(self.protocol)+" "+str(self.num_pck)+"]\n"

class IP_data:
    def __init__(self,s_ip):
        self.src_ip=ipaddress.IPv4Address(unicode(s_ip))
        self.ret_c=0 #with syn
        self.outord_c=0
	self.d_ack=0
        #self.ndns_c=0 #distinct flows        
        self.reset_c=0
        self.icmp_c=0
        self.dis_ret_ip=set()
        self.dis_ip=set()
        self.dis_by_16=set()
        #self.div_ratio=0
        self.no_p_in=0
        self.p_len_in=0
        self.no_p_out=0
        self.p_len_out=0
	self.ctrl_pck_c=0
        self.to_ip=[]
        
    def clear(self):
        self.ret_c=0 
        self.outord_c=0        
        self.reset_c=0
        self.icmp_c=0  
	self.d_ack=0      
        self.dis_ip.clear()
        self.dis_by_16.clear()
	self.dis_ret_ip.clear()      
        self.no_p_in=0
        self.p_len_in=0
        self.no_p_out=0
        self.p_len_out=0
	self.ctrl_pck_c=0
        del self.to_ip[:]
        
        
    def __repr__(self):
         return "["+str(self.src_ip)+" "+str(self.ret_c)+" "+str(len(self.dis_ret_ip))+" "+str(self.d_ack)+" "+str(self.outord_c)+" "+str(len(self.to_ip))+" "+str(self.reset_c)+" "+str(self.icmp_c)+" "+str(len(self.dis_by_16))+" "+str(self.ctrl_pck_c)+" "+str(self.no_p_in)+" "+str(self.p_len_in)+" "+str(self.no_p_out)+" "+str(self.p_len_out)+"]\n"

def get_ip_list():
	ip_data={}
	for ip in ip_chk:    
    		ip_data[ip]=IP_data(ip)       
	return ip_data

def by_16(ip):
    parts=ip.split('.')
    return parts[0]+"."+parts[1]+".0.0"

def parse():
	global par
	f=False
	ret=[]
	n=len(par)
	for i in range(len(par)):
		if par[i] == '\xe2\x86\x92' and not f:
			f=True
		elif par[i] == '\xe2\x86\x92' and i+2<n:
			ret.append(par[i-1])
			ret.append(par[i+1])
			break
	return ret
			
def add3():
	global par
	sip=par[2]
	dip=par[4]
	w_n=(int)(float(par[1]))/window
	if w_n in com_dat:
		record=com_dat[w_n]
		if sip in record:
			data=record[sip]
			data.ctrl_pck_c+=1			
				
			
def add2():
	global par
	sip=par[2]
	dip=par[4]
	sport=0
	dport=0
	w_n=(int)(float(par[1]))/window
	if w_n not in com_dat:
		com_dat[w_n]={}
	record=com_dat[w_n]
	if sip not in record:
		record[sip]=IP_data(sip)
	data=record[sip]
	data.no_p_out+=1
	if len(par)>7:
	       	data.p_len_out+=int(par[6])
        data.dis_ip.add(dip)
        data.dis_by_16.add(by_16(dip))
	port = parse()
	if port:
		sport=port[0]
		dport=port[1]
	todat=To_ip_data(dip,sport,dport,par[5])
       	if todat not in data.to_ip:
  	      data.to_ip.append(todat)
	else:
		for ip in data.to_ip:
			if ip==todat:
	        		ip.num_pck+=1
	if dip in record:
        	data=record[dip]
        	data.no_p_in+=1
		if len(par)>7:
	        	data.p_len_in+=int(par[6])



def add1(typ):
	global par
	sip=par[2]
	dip=par[4]
	w_n=(int)(float(par[1]))/window
	if w_n in com_dat:
		record=com_dat[w_n]				
		if sip in record:
			data=record[sip]
			for tok in par:
				if "Retransmission" in tok:
					data.ret_c+=1
					data.dis_ret_ip.add(dip)
				if tok == "Dup":
					data.d_ack+=1
				if "RST" in tok:
					data.reset_c+=1
				if "Out-Of-Order" in tok:
					data.outord_c+=1
				if tok == "ICMP":
						data.icmp_c+=1
			if dip in record:
				data=record[dip]
				if "ICMP" in par:
					data.icmp_c+=1		
	
		

def is_ipv4(ip):
	match = re.match("^(\d{0,3})\.(\d{0,3})\.(\d{0,3})\.(\d{0,3})$", ip)
	if not match:
		return False
	quad = []
	for number in match.groups():
		quad.append(int(number))
	if quad[0] < 1:
		return False
	for number in quad:
		if number > 255 or number < 0:
			return False
	return True

def WriteFile():
	f1=open("/home/amit/botnet/code2/detection/ex.csv","a+")
	
	for win in com_dat:		
		ip_dat=com_dat[win]
		for ip in ip_dat: 
			data = ip_dat[ip]
			feature=[]
			bbin=0
			bbout=0
			diversity=0
			if data.no_p_in!=0:
			    bbin=data.p_len_in/data.no_p_in
			if data.no_p_out!=0:
			    bbout=data.p_len_out/data.no_p_out
			if len(data.dis_by_16) != 0 :
			    diversity=float(len(data.dis_ip))/float(len(data.dis_by_16))                        
			    
			feature.append(data.ret_c)
			feature.append(len(data.dis_by_16))
			feature.append(diversity)
			feature.append(len(data.to_ip)) #write to_ip to different file
			feature.append(len(data.dis_ip))  
			feature.append(data.reset_c)
			feature.append(data.outord_c)
			feature.append(data.icmp_c)
			feature.append(data.no_p_out)
			feature.append(bbin)
			feature.append(bbout)
			feature.append(len(data.dis_ret_ip))
			feature.append(data.d_ack)
			feature.append(data.ctrl_pck_c)			
			wstr=""
			for zx in feature:
				wstr+=str(zx)+","			
			wstr=wstr[:-1]
			wstr+="\n"
			f1.write(wstr)
			
	f1.close()

def runCmd(typ,fl_nm):
	global par
	command= "tshark -r "+fl_nm+" -Y "+"'ip.version==4&&("+typ+")'"
#	print command
	p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)	
	for line in iter(p.stdout.readline, ''):
		line=line.strip()
		par=line.split()		
		if par and par[0]!='**' and len(par)>6:	
			
			try:						    				
				if is_ipv4(par[2]) and is_ipv4(par[4]):					
					if typ == "(tcp.analysis.retransmission&&tcp.flags.syn==1)||tcp.analysis.duplicate_ack||tcp.analysis.out_of_order||tcp.flags.reset==1||icmp.type==3":									
						add1(typ)
					elif typ == "ip.version==4":
						add2()
					elif typ == "!data.data":
						add3()
				else:
					continue
			except ValueError:
    				continue		
	retval = p.wait()

types = ["ip.version==4","(tcp.analysis.retransmission&&tcp.flags.syn==1)||tcp.analysis.duplicate_ack||tcp.analysis.out_of_order||tcp.flags.reset==1||icmp.type==3","!data.data"]
#types= ["!data.data"]
fl = "/home/amit/botnet/data/brett_dumps/natbox/natbox.20110217.pcap"

com_dat={}

window=600

"""
for ty in types:
	runCmd(ty,fl)
	print ty+" done"
#print com_dat
WriteFile()
#f2=open("/home/amit/botnet/data/model_data/data2/to_ip_p2pbox1.csv","a+")
"""
folder="/home/amit/botnet/code2/detection/"
fls=['ex.pcap','ex1.pcap']
cnt=1
for x in fls:		
	fl=folder+x
	print x+" "+str(cnt)
	for ty in types:
		runCmd(ty,fl)
		#print ty+" done"
	WriteFile()
	com_dat.clear()
	cnt+=1

