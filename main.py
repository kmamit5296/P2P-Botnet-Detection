from dataholders import IP_data,To_ip_data,FlowData
import cPickle as pickle
import pyshark
import time,re,threading,sys,ipaddress
 
dns_res = set()
ip_chk = [] #fill ip 
ip_dat1={}
ip_dat2={}
flow_dat1={}
flow_dat2={}
p2p_window = 60
bot_window = 3600
st_time = 0
end_time = 0
p2p_chk_thread = None
bot_chk_thread = None
p2p_detected = []
bot_detected = []
clf = None
clfbot = None
checking_p2p = True
checking_bot = False
choose_holder = True
choose_botholder = True
fp2p_detect = False
st_btime = 0
end_btime = 0

def printout(text,no):
	if no==1:
		print("\033[01m\033[31m{}\033[00m".format(text))
	else:
		print("\033[01m\033[32m{}\033[00m".format(text))

def get_features(key,flow_dat):
    dat = flow_dat[key]
    if dat.mxintertime == float(-sys.maxint-1):
        dat.mxintertime=0
    if dat.mnintertime == float(sys.maxint):
        dat.mnintertime = 0
    if dat.mxfwdintertime == float(-sys.maxint-1):
        dat.mxfwdintertime = 0
    if dat.mxbkdintertime == float(-sys.maxint-1):
        dat.mxbkdintertime = 0 
    if dat.mnfwdintertime == float(sys.maxint):
        dat.mnfwdintertime = 0
    if dat.mnbkdintertime == float(sys.maxint):
        dat.mnbkdintertime = 0
    if dat.fdp+dat.bdp-1 != 0:
        dat.meanintertime = (dat.las_ts - dat.f_ts)/(dat.fdp+dat.bdp-1)
    else:
        dat.meanintertime = 0
    dat.meanpkttime = dat.totalduration/(dat.fdp+dat.bdp)
    if dat.fdp-1 !=0:
        dat.meanfwdinter = (dat.lasfwd_ts-dat.ffwd_ts)/(dat.fdp-1)
    else:
        dat.meanfwdinter = 0
    if dat.fbkd_ts == None or dat.bdp-1 == 0:
        dat.meanbkdinter = 0
    else:
        dat.meanbkdinter = (dat.lasbkd_ts-dat.fbkd_ts)/(dat.bdp-1)
    outputFeature =[dat.meanintertime,dat.fdp,dat.bdp,dat.fwdbytes,dat.bkdbytes,dat.totdata,dat.pktsmall,dat.pktlarge,dat.mxintertime,dat.mnintertime,dat.totalduration,dat.meanpkttime,dat.meanfwdinter,dat.meanbkdinter,dat.mxfwdintertime,dat.mxbkdintertime,dat.mnfwdintertime,dat.mnbkdintertime]
    return outputFeature



def validate_bot_model(fet,flw):
	global clfbot
	pd = clfbot.predict([fet])[0]
	print fet,pd
	if pd == 1:
		if flw in flow_dat1.keys():
			del flow_dat1[flw]
		if flw in flow_dat2.keys():
			del flow_dat2[flw]
		if flw[0] in p2p_detected and flw[0] not in bot_detected:
			bot_detected.append(flw[0]) 
			p2p_detected.remove(flw[0])
		if flw[2] in p2p_detected and flw[2] not in bot_detected:
			bot_detected.append(flw[2]) 
			p2p_detected.remove(flw[2])
		printout("BOT"+str(flw),1) 	

def check_Bot_Host():
	global checking_bot
	j=0
    	try:	    
	    while True:
		if j%2==0:			
			for flw in flow_dat2.keys():
				fet_vec = get_features(flw , flow_dat2)
				if fet_vec[0] >= 50 and fet_vec:
					validate_bot_model(fet_vec,flw)
		else:
			for flw in flow_dat1.keys():
				fet_vec = get_features(flw , flow_dat1)				
				if fet_vec[0] >= 50 and fet_vec:
					validate_bot_model(fet_vec,flw)
		j+=1			
		checking_bot = False		
		while not checking_bot:
			pass
	except Exception as e:
		raise

	



def HandlePacket(pkt,flow_dat):
    global p2p_detected
    s_ip = pkt.ip.src
    d_ip = pkt.ip.dst
    if s_ip not in p2p_detected and d_ip not in p2p_detected:
        return
    prot_str=re.findall(r"([a-zA-Z0-9]*)\sLayer", str(pkt.layers))
    flag = 0
    
    if "TCP" in prot_str:
        flag = 1        
        flw = (s_ip,pkt.tcp.srcport,d_ip,pkt.tcp.dstport)
        flw2 = (d_ip,pkt.tcp.dstport,s_ip,pkt.tcp.srcport)
                
    elif "UDP" in prot_str:
        flag = 1        
        flw = (s_ip,pkt.udp.srcport,d_ip,pkt.udp.dstport)
        flw2 = (d_ip,pkt.udp.dstport,s_ip,pkt.udp.srcport)
   
    if flag == 1 and flw in flow_dat.keys():               
            dat=flow_dat[flw]      
            dat.fdp+=1
            dat.totdata+=int(pkt.length)
            if "TCP" in prot_str:
                dat.fwdbytes += int(pkt.layers[prot_str.index("TCP")].len)
                dat.tcp += 1
            elif "UDP" in prot_str:
                dat.fwdbytes += int(pkt.layers[prot_str.index("UDP")].length)
                dat.udp += 1
            dat.pktsmall = min(int(pkt.length),dat.pktsmall)
            dat.pktlarge = max(int(pkt.length),dat.pktlarge)
            dat.mxintertime = max(dat.mxintertime,float(pkt.sniff_timestamp)-dat.las_ts)
            dat.mnintertime = min(dat.mnintertime,float(pkt.sniff_timestamp)-dat.las_ts)
            dat.mxfwdintertime = max(dat.mxfwdintertime,float(pkt.sniff_timestamp)-dat.lasfwd_ts)
            dat.mnfwdintertime = min(dat.mnfwdintertime,float(pkt.sniff_timestamp)-dat.lasfwd_ts)            
            dat.totalduration = float(pkt.sniff_timestamp)-dat.f_ts
            dat.las_ts = dat.lasfwd_ts = float(pkt.sniff_timestamp)
                                    
            
    elif flag == 1 and flw2 in flow_dat.keys():            
            dat=flow_dat[flw2]
            dat.bdp+=1
            dat.totdata+=int(pkt.length)
            if "TCP" in prot_str:
                dat.bkdbytes += int(pkt.layers[prot_str.index("TCP")].len)
                dat.tcp +=1
            elif "UDP" in prot_str:
                dat.bkdbytes += int(pkt.layers[prot_str.index("UDP")].length)
                dat.udp +=1
            dat.pktsmall = min(int(pkt.length),dat.pktsmall)
            dat.pktlarge = max(int(pkt.length),dat.pktlarge)
            dat.mxintertime = max(dat.mxintertime,float(pkt.sniff_timestamp)-dat.las_ts)
            dat.mnintertime = min(dat.mnintertime,float(pkt.sniff_timestamp)-dat.las_ts)
            dat.totalduration = float(pkt.sniff_timestamp)-dat.f_ts
            if dat.fbkd_ts is None:
                dat.las_ts = dat.lasbkd_ts = dat.fbkd_ts = float(pkt.sniff_timestamp)
            else:
                dat.mxbkdintertime = max(dat.mxbkdintertime,float(pkt.sniff_timestamp)-dat.lasbkd_ts)
                dat.mnbkdintertime = min(dat.mnbkdintertime,float(pkt.sniff_timestamp)-dat.lasbkd_ts)
                dat.las_ts = dat.lasbkd_ts = float(pkt.sniff_timestamp)            
            
    elif flag == 1:           
            dat=flow_dat[flw]=FlowData()            
            dat.fdp+=1
            if "TCP" in prot_str:
                dat.fwdbytes += int(pkt.layers[prot_str.index("TCP")].len)
                dat.tcp +=1
            elif "UDP" in prot_str:
                dat.fwdbytes += int(pkt.layers[prot_str.index("UDP")].length)
                dat.udp +=1
            dat.pktsmall = dat.pktlarge = dat.totdata = int(pkt.length)
            dat.f_ts = dat.las_ts = dat.lasfwd_ts = dat.ffwd_ts = float(pkt.sniff_timestamp)            
            



def setupbotchk():
	global st_btime
	global clfbot
	clfbot = pickle.load(open("./models/MODEL_AC.pickle","rb"))
	#st_btime = int(float(time.time()))
	bot_chk_thread = threading.Thread(target=check_Bot_Host) #check this
	bot_chk_thread.daemon = True
	bot_chk_thread.start()
	#start bot checker
	#initialise	
	
def addData(v1,v2):
    v1.ret_c+=v2.ret_c
    v1.outord_c+=v2.outord_c
    v1.reset_c+=v2.reset_c
    v1.icmp_c+=v2.icmp_c
    v1.no_p_in+=v2.no_p_in
    v1.no_p_out+=v2.no_p_out
    v1.p_len_out+=v2.p_len_out
    v1.p_len_in+=v2.p_len_in
    v1.d_ack+=v2.d_ack
    v1.ctrl_pck_c+=v2.ctrl_pck_c
    for tod in v2.to_ip:
        if tod not in v1.to_ip:
            v1.to_ip.append(tod)
            
    for tod in v2.dis_ip:
        if tod not in v1.dis_ip:
            v1.dis_ip.add(tod)
    for tod in v2.dis_by_16:
        if tod not in v1.dis_by_16:
            v1.dis_by_16.add(tod)
    for tod in v2.dis_ret_ip:
        if tod not in v1.dis_ret_ip:
            v1.dis_ret_ip.add(tod)



def getFeature(g):    
    del g[1]
    del g[1]
    h = [0]*12
    h[0]=g[0]
    h[1]=g[4]
    h[2]=g[7]
    h[3]=g[8]
    h[4]=g[9]
    h[5]=g[2]
    h[6]=g[1]
    h[7]=g[3]
    h[8]=g[10]
    h[9]=g[5]
    h[10]=g[6]
    h[11]=g[11]
    return h

def validate(f,ip):
    global fp2p_detect
    #h=getFeature(f)
    pd2=clf.predict([f])[0]
    print f,pd2
    if pd2 == 1:
	if not fp2p_detect:
		st_btime = int(float(time.time()))
		fp2p_detect = True
		setupbotchk()
	if ip in ip_dat1.keys():
		del ip_dat1[ip]
	if ip in ip_dat2.keys():
		del ip_dat2[ip]
	if ip in ip_chk:
		ip_chk.remove(str(ip))
	if ip not in p2p_detected:
		p2p_detected.append(ip)
	#delete data in ip_dat for this ip
    	printout("P2P Detected ip: "+str(p2p_detected),1)
    else:
	printout("Not P2P",0)


def ModelRead():
	global clf	
	clf = pickle.load(open("./models/hostdetect.p","rb"))

def check_Host():
    global checking_p2p
    j=0
    cnt=0
    ips_data={}
    try:
	    ModelRead()
	    for ip in ip_chk:    
		ips_data[ip]=IP_data(ip)
	    while True:
		if j%2 == 0:
		    cnt+=1
		    for ip in ip_chk:
		        #print "11 "+str(ip_dat1)+" "+str(ip_dat2)+" "+str(cnt)
		        addData(ips_data[ip],ip_dat2[ip])
		else:
		    cnt+=1
		    for ip in ip_chk:
		        #print "22 "+str(ip_dat1)+" "+str(ip_dat2)+" "+str(cnt)
		        addData(ips_data[ip],ip_dat1[ip])
		j+=1

			#validate ips_data with model
		for ip in ips_data:
		    data = ips_data[ip]
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
		    feature.append(len(data.to_ip))
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
	 	    validate(feature,ip)
		if cnt == 10:
		    #clear data of last period
		    cnt = 0            
		    for ip in ips_data:
		        print "clearing.."
		        ips_data[ip].clear()
		checking_p2p = False
		while not checking_p2p:
			pass
    except Exception as e:
	print e
	raise


def by_16(ip):
    parts=ip.split('.')
    return parts[0]+"."+parts[1]+".0.0"

def handle_pkt(pkt,ip_dat):
    #print pkt.number
    s_ip = pkt.ip.src
    d_ip = pkt.ip.dst    
    if s_ip in ip_dat:
        dat=ip_dat[s_ip]
        dat.no_p_out+=1
        dat.p_len_out+=int(str(pkt.length))
        dat.dis_ip.add(d_ip)
        dat.dis_by_16.add(by_16(d_ip))        
        prot_str=re.findall(r"([a-zA-Z0-9]*)\sLayer", str(pkt.layers))
        if "TCP" in prot_str:
            todat=To_ip_data(pkt.ip.dst,pkt.tcp.srcport,pkt.tcp.dstport,str(pkt.highest_layer))
            if todat not in dat.to_ip:
                dat.to_ip.append(todat)
            else:
                for ip in dat.to_ip:
                    if ip==todat:
                        ip.num_pck+=1
            if 'analysis_retransmission' in pkt.tcp.field_names:                
                dat.ret_c+=1
                dat.dis_ret_ip.add(d_ip)
            if 'analysis_out_of_order' in pkt.tcp.field_names:
                dat.outord_c+=1                
            if 'analysis_duplicate_ack' in pkt.tcp.field_names:
                dat.d_ack+=1
            if pkt.tcp.flags_reset.int_value:                
                dat.reset_c+=1
	    if "DATA" not in prot_str:
		dat.ctrl_pck_c+=1

        elif "ICMP" in prot_str:
            todat=To_ip_data(d_ip,0,0,str(pkt.highest_layer))
            if todat not in dat.to_ip:
                dat.to_ip.append(todat)
            else:
                for ip in dat.to_ip:
                    if ip==todat:
                        ip.num_pck+=1
            if pkt.layers[prot_str.index("ICMP")].type == '3':
                #print pkt.number
                dat.icmp_c+=1
        elif "UDP" in prot_str:
            todat=To_ip_data(pkt.ip.dst,pkt.udp.srcport,pkt.udp.dstport,str(pkt.highest_layer))            
            if todat not in dat.to_ip:
                dat.to_ip.append(todat)
            else:
                for ip in dat.to_ip:
                    if ip==todat:
                        ip.num_pck+=1
	    if "DATA" not in prot_str:
		dat.ctrl_pck_c+=1     
        else:
            todat=To_ip_data(pkt.ip.dst,0,0,str(pkt.highest_layer))            
            if todat not in dat.to_ip:
                dat.to_ip.append(todat)
            else:
                for ip in dat.to_ip:
                    if ip==todat:
                        ip.num_pck+=1
	    if "DATA" not in prot_str:
		dat.ctrl_pck_c+=1
    if d_ip in ip_dat:
	prot_str=re.findall(r"([a-zA-Z0-9]*)\sLayer", str(pkt.layers))
        dat=ip_dat[d_ip]
        dat.no_p_in+=1
        dat.p_len_in+=int(str(pkt.length))
        if "ICMP" in str(pkt.layers):
            if pkt.layers[prot_str.index("ICMP")].type == '3':
                #print pkt.number
                dat.icmp_c+=1
	if "DATA" not in str(pkt.layers):
		dat.ctrl_pck_c+=1




def initialise():
	for ip in ip_chk:    
		ip_dat1[ip]=IP_data(ip)
	for ip in ip_chk:    
		ip_dat2[ip]=IP_data(ip)

def stp2pChkThread():
	p2p_chk_thread = threading.Thread(target=check_Host)
	p2p_chk_thread.daemon = True
	p2p_chk_thread.start()

def checkTime(i,pkt):
	global end_time
	global st_time
	global checking_p2p
	global choose_holder
	#end_time=int(float(time.time()))
	end_time=int(float(pkt.sniff_timestamp))
	if end_time-st_time >= p2p_window:
		checking_p2p = True	    
		if i%2 == 0:
			choose_holder = False
			for ip in ip_chk:    
				ip_dat2[ip].clear()
		else:
			choose_holder = True
			for ip in ip_chk:    
                		ip_dat1[ip].clear()
		st_time = end_time
		return True
	return False

def checkBotTime(j,pkt):
	global st_btime
	global end_btime
	global choose_botholder
	global checking_bot
	#endb_time=int(float(time.time()))
	endb_time=int(float(pkt.sniff_timestamp))	
	if endb_time-st_btime >= bot_window:
		checking_bot = True	    
		if j%2 == 0:
			choose_botholder = False
			flow_dat2.clear()
		else:
			choose_botholder = True
                	flow_dat1.clear()
		st_btime = endb_time
		return True
	return False

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

def check_dns(pkt):
	if(("DNS" in str(pkt.layers)) ) or (("MDNS" in str(pkt.layers)) ):            
		str_pkt=str(pkt.layers[-1])
		res_ips = re.findall(r"addr\s(.*)", str_pkt)
        	for x in res_ips:
            		if is_ipv4(x):
                		dns_res.add(x)
   	elif pkt.ip.src in dns_res or pkt.ip.dst in dns_res:
		return True
	return False
			
def start(iface = 'eno1', capture_filter = 'ip'):
	global st_time
	global st_btime
	global fp2p_detect
	initialise()
	stp2pChkThread()
	cap = pyshark.LiveCapture(interface=iface ,bpf_filter= capture_filter)
	#cap = pyshark.FileCapture('/home/amit/botnet/data/vinchuca/abc2.pcap',display_filter='ip.version==4')
	st_time = int(float(time.time()))
	i = 0
	j = 0
	for pkt in cap.sniff_continuously():
		s_ip = ipaddress.IPv4Address(unicode(str(pkt.ip.src)))
		d_ip = ipaddress.IPv4Address(unicode(str(pkt.ip.dst)))

		if(s_ip.is_multicast or d_ip.is_multicast): #skip multicast ip address
			continue

		if fp2p_detect:
			if checkBotTime(j,pkt):
				j+=1
		if checkTime(i,pkt):
			i+=1
		if not check_dns(pkt):
			if choose_holder:
				handle_pkt(pkt,ip_dat1)
			else:
				handle_pkt(pkt,ip_dat2)
			if choose_botholder and fp2p_detect:				
				HandlePacket(pkt,flow_dat1)
			elif choose_botholder and fp2p_detect:	
				HandlePacket(pkt,flow_dat2)

			
