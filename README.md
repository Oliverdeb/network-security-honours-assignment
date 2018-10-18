<!-- Markdown - please view in markdown viewer  -->
# Install dependencies
`Python3` and `virtualenv` are required for the Makefile to install the `pycrypto`.

On Ubuntu/Bash for windows the following can be run to install python3 and virtualenv
```shell
sudo apt-get install python3 virtualenv
```

Follow [this link](https://programwithus.com/learn-to-code/Pip-and-virtualenv-on-Windows/) to get virtualenv installed on Windows.

Once python3 and vitualenv are present on the system, the Makefile can create a local virtualenv and install pycrypto into it.

```shell
make setup
```

# To run
To run, the server must be started first.

Open two terminal sessions and from the same directory as the project run  `make server` and in the other session run  `make client`. 

This will start the server, wait for the client to connect and then begin Diffie-Hellman key exchange before allowing you to chat.

## Note: This is only configured to work on a single machine (ie. localhost). You can change the IP and port in the first few lines of server.py and client.py if you want it to work over LAN.