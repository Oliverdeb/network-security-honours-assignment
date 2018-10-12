
server:
	./venv/bin/python3 server.py

client:
	./venv/bin/python3 client.py

run: server client

setup:
	if [ ! -f ./venv/bin/pip ]; then \
			virtualenv -p python3 ./venv; fi

	./venv/bin/pip install -Ur requirements.txt

clean:
	@rm -rf ./venv