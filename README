This is test/sample for using NZSDK DH algrothim.

Run steps:
0. Set your NZDIR to NZSDK lib/include directory.

1. ./autogen.sh

2. ./configure --prefix=`pwd`/install

3. make

4. make install

All the binary files located at `pwd`/install

5. update system kernel parameter, reduce TIME_WAIT/CLOSE_WAIT time windows for server
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

sudo sysctl -w net.ipv4.tcp_syncookies=1
sudo sysctl -w net.ipv4.tcp_tw_reuse=1
sudo sysctl -w net.ipv4.tcp_tw_recycle=1
sudo sysctl -w net.ipv4.tcp_fin_timeout=30

6. boot server:
	cd `pwd`/install/bin; ./nzsdk_svr_ev >svr.log 2>&1 &

7. run client in another machine:(You must run step0-step4 before run your client in new machine!)
	cd `pwd`/install/bin; ./nzsdk_clt_ev <server host> <port> <duration> >clt.log 2>&1

8. Any agreeScret dose not match between server and client, will print the publickeys and agreeScrets.

9. monitor system statue:
	netstat -n | awk '/^tcp/ {++S[$NF]} END {for(a in S) print a, S[a]}'

	
