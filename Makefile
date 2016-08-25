all:
	go build -o webapp/golang/app

setup:
	go get -u .

restart:
	sudo systemctl restart isu-go	

