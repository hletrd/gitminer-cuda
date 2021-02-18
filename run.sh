#!/bin/bash
for i in {0..14}
do
	./sha1f_cuda $i log$i.txt result$i.txt &
done
