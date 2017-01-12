# DH_exchange_svr_clt
Exchange agree secret between client and server.
This is test/sample for using ORACLE database security libary NZSDK.  
And will add new features such as rich communicate support, dynamic regist/unregist service and so on.

Run steps:
0. Set your NZDIR to NZSDK lib/include directory.

1. ./autogen.sh

2. ./configure --prefix=`pwd`/install

3. make

4. make install

All the binary files located at `pwd`/install

5. boot server:
	cd `pwd`/install/bin; ./dhsvr_ondmand <port> >svr.log 2>&1 &

6. run client in another machine:(You must run step0-step4 before run your client in new machine!)
	cd `pwd`/install/bin; ./dhclt <server host> <port> <duration> >clt.log 2>&1

7. Any agreeScret dose not match between server and client, will print the publickeys and agreeScrets.


	
