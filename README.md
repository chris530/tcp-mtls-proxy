export localmtlsport=5556
export remote_addr_and_port="localhost:4444"
export certdirpath="./"
export nounsecure=true

go run ./server.go

curl --key tls.key --cert tls.crt -k https://localhost:5556

=== UnSecure proxy

export localport=3333
export remote_addr_and_port=localhost:4444
