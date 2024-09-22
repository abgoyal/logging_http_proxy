
# Simple http proxy with logging


This is a VERY basic http proxy that keeps detailed logs of the requests and responses passing thru it in a sqlite db.
This is mainly useful for debugging http endpoints or reverse-engineering http apis. 

It records:

* request method
* url
* request body 
* request headers
* request body length
* response body
* response headers
* response body length
* roundtrip duration
* timestamp of request.

It outputs a log on stdout with all of these details, except the bodies and headers.

The complete logs with full request/response bodies and headers are stored in a sqlite db. The sqlite db is created if it does not
exist in the current working directory.

It listens on two ports (default 8080 for http and 8081 for https). The https port is always 1 plus the http port. 

For https, it generates self-signed certs on the fly and saves them in the current working directory. If you want to use
your own cert and key, just place them with the right filenames in the working directory and they will be used. 

If you use the self-signed certs, you may need to click-thru warnings from your browser and/or add the cert to your browser
trust store.


# compiling


```
go mod tidy
go build
```

# running

```
./htproxy --listen-port int -upstream-url string
```

upstream-url is a required command line param, and the listen port is optional. The proxy will listen to the
provided port (or the default 8080) as an http server, and on the provided port + 1 (or the default 8081)
as an https server.


