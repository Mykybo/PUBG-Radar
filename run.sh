sudo java -jar target/pubg-radar-1.0-SNAPSHOT-jar-with-dependencies.jar $(ip -f inet -o addr show enp0s25|cut -d\  -f 7 | cut -d/ -f 1) PortFilter $1
