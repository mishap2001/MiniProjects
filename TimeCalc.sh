#!/bin/bash

###############################################################
# Domain Mapper 
# Author: Michael Pritsert
# GitHub: https://github.com/mishap2001
# LinkedIn: https://www.linkedin.com/in/michael-pritsert-8168bb38a
# License: MIT License
###############################################################


echo "
 ┌─────────────────────┐
 │   ⏱  TIME CALC      │
 └─────────────────────┘
"
function MENU()
{
echo "[*] What would you like to calculate?"
while true; do
echo "[1] Time between hours"
echo "[2] Time between dates"
echo "[3] Epoch converter"
read menu_ans
case $menu_ans in
	1) HOURS
	   break
	;;   
	2) DATES
	   break
	;; 
	3) EPOCH
	   break
	;;  
	*) echo "[!] Invalid choice."
	   echo "Choose from the listed options."
	   echo
	;;
esac
done
}

function HOURS()
{
echo
echo "[*] Enter Starting Time (HH:MM:SS):"
read start
echo
echo "[*] Enter Finish Time (HH:MM:SS):"
read finish
echo
echo "[*] If you want to include days, enter the number. If not, press ENTER to skip:"
read days

start_sec=$(echo "$start" | awk -F: '{print $1*3600 + $2*60 + $3}')
finish_sec=$(echo "$finish" | awk -F: '{print $1*3600 + $2*60 + $3}')
final_sec=$((finish_sec - start_sec ))

if [ -n "$days" ]; then
final_sec=$(( final_sec + days*86400 ))
else
days=0
fi

final_min=$(( final_sec / 60 ))
remaining=$(( final_sec % 60 ))
hours=$(( final_sec / 3600 ))
minutes=$(( (final_sec % 3600) / 60 ))

echo
echo "[*] Time passed between entered times:"
echo "[S] - $final_sec seconds"
echo "[M] - $final_min minutes and $remaining seconds"
echo "[H] - $hours hours, $minutes minutes and $remaining seconds"
echo "[D] - $days days, $hours hours, $minutes minutes and $remaining seconds"
echo
}

function DATES()
{
echo
echo "[*] Enter Starting Date (DDMMYYYY):"
read start_d
echo
echo "[*] Enter Finish Date (DDMMYYYY):"
read end_d

function to_iso()
{
    echo "${1:4:4}-${1:2:2}-${1:0:2}"
}

start_iso=$(to_iso "$start_d")
end_iso=$(to_iso "$end_d")

y1=$(date -d "$start_iso" +%Y)
m1=$(date -d "$start_iso" +%m)
d1=$(date -d "$start_iso" +%d)

y2=$(date -d "$end_iso" +%Y)
m2=$(date -d "$end_iso" +%m)
d2=$(date -d "$end_iso" +%d)

years=$((y2 - y1))
months=$((m2 - m1))
days=$((d2 - d1))

if [ $days -lt 0 ]; then
months=$((months - 1))
days=$((days + 30))
fi

if [ $days -lt 0 ]; then
months=$((months - 1))
days=$((days + $(date -d "$end_iso" +%d)))
fi


echo
echo "[*] The time between the dates is:"
echo "$years years, $months months, $days days"
}

function EPOCH()
{
echo
echo "[*] Enter the epoch time for conversion:"
read time_to_convert
con_time=$(date -d @"$time_to_convert")
echo
echo "[*] The entered epoch time is: $time_to_convert"
echo "[**] The epoch time after conversion is: $con_time"
}
MENU
