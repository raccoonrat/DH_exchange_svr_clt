LOOP=1
while [ true ]; do
	cp clt.log tmp.log
	total=`grep "50 total" tmp.log |wc -l`
	succ=`grep "Succed in" clt.log |wc -l`
	#echo "total=$total"
	#echo "succ=$succ"
	Resu=`echo "scale=5;$total*50" |bc`
	
	if [ $Resu != $succ ]
		then
			echo "Total num <$Resu>, Success num <$succ> in $LOOP"
		else
			echo "So far success in loog:$LOOP, the total num is $Resu" 
	fi

	LOOP=`expr $LOOP + 1`
	sleep 120
done

