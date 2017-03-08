sudo sysctl net.ipv4.tcp_keepalive_time
sudo sysctl net.ipv4.tcp_keepalive_probes
sudo sysctl net.ipv4.tcp_keepalive_intvl
sudo sysctl net.ipv4.tcp_syncookies 
sudo sysctl net.ipv4.tcp_tw_reuse 
sudo sysctl net.ipv4.tcp_tw_recycle
sudo sysctl net.ipv4.tcp_fin_timeout

sudo sysctl -w net.ipv4.tcp_keepalive_time=1200  
sudo sysctl -w net.ipv4.tcp_keepalive_probes=2 
sudo sysctl -w net.ipv4.tcp_keepalive_intvl=10

#vi /etc/sysctl.conf 


#next is test another argument for tune
sudo sysctl -w net.ipv4.tcp_syncookies=1 
sudo sysctl -w net.ipv4.tcp_tw_reuse=1 
sudo sysctl -w net.ipv4.tcp_tw_recycle=1 
sudo sysctl -w net.ipv4.tcp_fin_timeout=30 

