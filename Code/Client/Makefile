if [[ -d "./bin" ]]; then
	rm -R bin/* 2> /dev/null
else
	mkdir bin
fi

g++ -c ../Misc/Encryption.cpp
g++ -c Client/Client.cpp
g++ -c main.cpp
g++ -o bin/Client main.o Client.o Encryption.o -lpthread -lcrypto

chmod 777 bin/*

rm *.o