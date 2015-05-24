#!/bin/bash

while true; do 
	inotifywait -q -e CREATE -r --exclude "\\.(o|swp)$" src
	make clean && make
done
