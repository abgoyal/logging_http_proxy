package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

var db *sql.DB

// Initialize SQLite Database
func initDB() {
	var err error
	db, err = sql.Open("sqlite3", "./proxy_logs.db")
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS proxy_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp TEXT,
			method TEXT,
			url TEXT,
			request_headers TEXT,
			request_body TEXT,
			response_status INTEGER,
			response_headers TEXT,
			response_body TEXT,
			request_body_length INTEGER,
			response_body_length INTEGER,
			duration_ms INTEGER
		)
	`)
	if err != nil {
		log.Fatalf("Failed to create table: %v", err)
	}
}

// Log to SQLite
func logToDB(logEntry map[string]interface{}) {
	_, err := db.Exec(`
		INSERT INTO proxy_logs
			(timestamp, method, url, request_headers, request_body, response_status,
			 response_headers, response_body, request_body_length, response_body_length, duration_ms)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		logEntry["timestamp"], logEntry["method"], logEntry["url"], logEntry["request_headers"],
		logEntry["request_body"], logEntry["response_status"], logEntry["response_headers"],
		logEntry["response_body"], logEntry["request_body_length"], logEntry["response_body_length"],
		logEntry["duration_ms"],
	)

	if err != nil {
		log.Printf("Error logging to DB: %v", err)
	}
}

// A custom ResponseWriter that captures the response for logging
type responseLogger struct {
	http.ResponseWriter
	statusCode int
	body       strings.Builder
}

func (rl *responseLogger) WriteHeader(statusCode int) {
	rl.statusCode = statusCode
	rl.ResponseWriter.WriteHeader(statusCode)
}

func (rl *responseLogger) Write(body []byte) (int, error) {
	rl.body.Write(body)
	return rl.ResponseWriter.Write(body)
}

// Generate a self-signed certificate for HTTPS if it doesn't exist
func generateSelfSignedCert(certFile, keyFile string) error {
	// Check if cert and key already exist
	if _, err := os.Stat(certFile); err == nil {
		if _, err := os.Stat(keyFile); err == nil {
			return nil
		}
	}

	// Generate private key
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %v", err)
	}

	// Create a template for the certificate
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Go Proxy Self-Signed"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		BasicConstraintsValid: true,
	}

	// Create a certificate
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %v", err)
	}

	// Write cert to file
	certOut, err := os.Create(certFile)
	if err != nil {
		return fmt.Errorf("failed to open %s for writing: %v", certFile, err)
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	certOut.Close()

	// Write key to file
	keyOut, err := os.Create(keyFile)
	if err != nil {
		return fmt.Errorf("failed to open %s for writing: %v", keyFile, err)
	}
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	keyOut.Close()

	return nil
}

// Proxy handler using httputil.ReverseProxy
func proxyHandler(target *url.URL) http.Handler {
	proxy := httputil.NewSingleHostReverseProxy(target)

	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		startTime := time.Now()

		// Initialize the log entry map
		logEntry := map[string]interface{}{
			"timestamp":       time.Now().Format(time.RFC3339),
			"method":          req.Method,
			"url":             req.URL.String(),
			"request_headers": fmt.Sprintf("%v", req.Header),
		}

		// Capture the original request body
		var reqBodyBytes []byte
		if req.Body != nil {
			reqBodyBytes, _ = io.ReadAll(req.Body)
		}

		// Restore the body so that the original request can still proceed
		req.Body = io.NopCloser(strings.NewReader(string(reqBodyBytes)))

		// Log request body size to the logEntry
		logEntry["request_body"] = string(reqBodyBytes)
		logEntry["request_body_length"] = len(reqBodyBytes)

		// Create a response logger to capture the response
		rl := &responseLogger{ResponseWriter: w, statusCode: http.StatusOK}

		// Proxy the request
		proxy.ServeHTTP(rl, req)

		// Capture response body and log it in the DB (not the console)
		respBody := rl.body.String()

		// Log response details to the database
		duration := time.Since(startTime).Milliseconds()
		logEntry["response_status"] = rl.statusCode
		logEntry["response_headers"] = fmt.Sprintf("%v", w.Header())
		logEntry["response_body"] = respBody
		logEntry["response_body_length"] = len(respBody)
		logEntry["duration_ms"] = duration

		// Log to the database
		logToDB(logEntry)

		// Log the final result to the console (excluding bodies)
		log.Printf("%d\t%d ms\trequestBytes %d\trespBytes %d\t%s\t%s",
			logEntry["response_status"], logEntry["duration_ms"], logEntry["request_body_length"], logEntry["response_body_length"], logEntry["method"], logEntry["url"])
	})
}

func main() {
	// Initialize flags for command-line parameters
	listenPort := flag.Int("listen-port", 8080, "Port on which the proxy listens for HTTP")
	upstreamURL := flag.String("upstream-url", "", "Upstream URL to forward requests to")
	flag.Parse()

	// Validate required params
	if *upstreamURL == "" {
		fmt.Println("Error: --upstream-url is a required parameter.")
		flag.Usage()
		return
	}

	// Initialize DB
	initDB()
	defer db.Close()

	// Parse the target URL for the proxy
	targetURL, err := url.Parse(*upstreamURL)
	if err != nil {
		log.Fatalf("Failed to parse target URL: %v", err)
	}

	// Generate or load self-signed certificates for HTTPS
	certFile := "cert.pem"
	keyFile := "key.pem"
	err = generateSelfSignedCert(certFile, keyFile)
	if err != nil {
		log.Fatalf("Failed to generate or load certificates: %v", err)
	}

	// Start the HTTP and HTTPS proxy servers
	httpPort := *listenPort
	httpsPort := httpPort + 1

	// HTTP server
	go func() {
		log.Printf("Starting HTTP proxy on :%d, forwarding to %s", httpPort, *upstreamURL)
		log.Fatal(http.ListenAndServe(":"+strconv.Itoa(httpPort), proxyHandler(targetURL)))
	}()

	// HTTPS server
	server := &http.Server{
		Addr:    ":" + strconv.Itoa(httpsPort),
		Handler: proxyHandler(targetURL),
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}

	log.Printf("Starting HTTPS proxy on :%d, forwarding to %s", httpsPort, *upstreamURL)
	log.Fatal(server.ListenAndServeTLS(certFile, keyFile))
}
