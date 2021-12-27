NAME = k8s-webhook
OWNER = me
MOD = k8s-webhook
VERSION = v1

deploy: docker
	docker run -d -p 8443:8443 $(NAME):$(VERSION)

docker: app
	docker build -t $(NAME):$(VERSION) .

app: deps
	CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o $(NAME) ./src/webhook.go

#bug with golang dependensies, pull requared modules manually
deps: mod
	./fix.ps1 v1.15.5
	go get ./...

mod: clean
	go mod init github.com/$(OWNER)/$(MOD)

clean:
	rm -f go.mod
	rm -f go.sum
	rm -f $(NAME)
