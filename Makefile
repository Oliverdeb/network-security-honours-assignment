run: setup server client

server:
	./venv/bin/python3 server.py

client:
	./venv/bin/python3 client.py

setup:
	if [ ! -f ./venv/bin/pip ]; then \
		virtualenv -p python3 ./venv; \
		./venv/bin/pip install -Ur requirements.txt; \
	fi	

clean:
	@rm -rf ./venv