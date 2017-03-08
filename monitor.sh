netstat -n | awk '/^tcp/ {++S[$NF]} END {for(a in S) print a, S[a]}'

echo "server fd:"
ps -ef|grep nzsdk_svr |grep -v grep |grep -v gdb | awk '{print $2}' |xargs lsof -a -p
echo "client fd:"
ps -ef|grep nzsdk_clt |grep -v grep |grep -v gdb | awk '{print $2}' |xargs lsof -a -p

ss -tan 'sport = :5555' | awk '{print $(NF)" "$(NF-1)}' |  \
	sed 's/:[^ ]*//g' | sort | uniq -c
