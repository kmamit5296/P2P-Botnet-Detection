import sys

class To_ip_data:
    def __init__(self,d_ip,s_port,d_port,prot):
        self.dst_ip=d_ip
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
        self.src_ip=s_ip
        self.ret_c=0 #with syn
        self.outord_c=0
        self.d_ack=0  #new done
        #self.ndns_c=0 #distinct flows        
        self.reset_c=0
        self.icmp_c=0
        self.dis_ret_ip=set() # new done
        self.dis_ip=set()
        self.dis_by_16=set()
        #self.div_ratio=0
        self.no_p_in=0
        self.p_len_in=0
        self.no_p_out=0
        self.p_len_out=0 
        self.ctrl_pck_c=0 # new 
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
         return "["+str(self.src_ip)+" "+str(self.ret_c)+" "+str(len(self.dis_ret_ip))+" "+str(self.d_ack)+" "+str(self.outord_c)+" "+str(len(self.to_ip))+" "+str(self.reset_c)+" "+str(self.icmp_c)+" "+str(len(self.dis_by_16))+" "+str(self.ctrl_pck_c)+" "+str(self.no_p_in)+" "+str(self.p_len_in)+" "+str(self.no_p_out)+" "+str(self.p_len_out)+"]"


            
class FlowData:
    def __init__(self):
        self.meanintertime = 0 
        self.fwdbytes = 0 #only data
        self.bkdbytes = 0
        self.fdp=0
        self.bdp=0
        self.totdata=0 #including headers
        self.pktsmall=0
        self.pktlarge=0
        self.mxintertime=float(-sys.maxint-1)
        self.mnintertime=float(sys.maxint)
        self.totalduration=0
        self.meanpkttime = 0 #duration/no pkt check
        self.meanfwdinter = 0
        self.meanbkdinter = 0
        self.mxfwdintertime = float(-sys.maxint-1)
        self.mxbkdintertime = float(-sys.maxint-1)
        self.mnfwdintertime = float(sys.maxint)
        self.mnbkdintertime = float(sys.maxint)
        #self.proto = 0 #udp or tcp
        self.ffwd_ts = None
        self.fbkd_ts = None
        self.las_ts = None
        self.lasfwd_ts = None
        self.lasbkd_ts = None
        self.f_ts = None
        self.tcp = 0
        self.udp = 0
            

class InspectIp:
	def __init__(self,ip):
		self.ip=ip
		self.status = "Normal"
