package main

import (
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net"
	"os"

	"golang.org/x/crypto/ssh"
)

var (
	orgID = ""

	//cli flags

	// bastion config to ssh connection

)

func main() {

	fmt.Println("started printing")

	// the below configs should be populated through CLI

	bastionConfig := BastionConfig{
		Host:           "", // or IP address
		Port:           22,
		User:           "", // or "ubuntu" depending on your AMI
		PrivateKeyPath: "",
	}

	postgreConfig := Config{
		Port:     1,
		User:     "",
		Password: "",
		DBName:   "",
		Host:     "",
	}

	// Connect to database through SSH tunnel
	db, err := connectToDB(bastionConfig, postgreConfig)
	if err != nil {
		fmt.Printf("Failed to connect: %v\n", err)
		return
	}
	defer db.Close()

	// Test the connection
	var version string
	err = db.QueryRow("SELECT version()").Scan(&version)
	if err != nil {
		fmt.Printf("Failed to query database: %v\n", err)
		return
	}

	fmt.Printf("Successfully connected to PostgreSQL: %s\n", version)
}

// BastionConfig holds the configuration for connecting to the bastion
type BastionConfig struct {
	Host           string // bastion host address
	Port           int    // SSH port (usually 22)
	User           string // SSH user (e.g., "ec2-user")
	PrivateKeyPath string // path to your .pem file
}

// ConnectToBastion establishes an SSH connection to the bastion host
func ConnectToBastion(config BastionConfig) (*ssh.Client, error) {
	// Read the private key file
	privateKeyBytes, err := os.ReadFile(config.PrivateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key: %v", err)
	}

	// Parse the private key
	signer, err := ssh.ParsePrivateKey(privateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %v", err)
	}

	// Define the SSH client configuration
	sshConfig := &ssh.ClientConfig{
		User: config.User,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		// In production, use proper host key verification
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	// Create the connection string
	addr := fmt.Sprintf("%s:%d", config.Host, config.Port)

	// Connect to the bastion
	client, err := ssh.Dial("tcp", addr, sshConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to bastion: %v", err)
	}

	return client, nil
}

func connectToDB(bastionConfig BastionConfig, dbConfig Config) (*sql.DB, error) {
	// First establish SSH connection (from previous example)
	sshClient, err := ConnectToBastion(bastionConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to bastion: %v", err)
	}

	// Step 1: Establish local listener
	// Using port 0 lets the system assign a random available port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("failed to establish local listener: %v", err)
	}
	defer listener.Close()

	// Get the randomly assigned local port
	localAddr := listener.Addr().(*net.TCPAddr)

	// Step 2: Start port forwarding goroutine
	go func() {
		for {
			// Accept local connections
			localConn, err := listener.Accept()
			if err != nil {
				fmt.Printf("Failed accepting local connection: %v\n", err)
				return
			}

			// Establish connection to PostgreSQL through SSH tunnel
			remoteConn, err := sshClient.Dial("tcp",
				fmt.Sprintf("%s:%d", dbConfig.Host, dbConfig.Port))
			if err != nil {
				fmt.Printf("Failed to connect to remote: %v\n", err)
				localConn.Close()
				continue
			}

			// Handle the tunnel bi-directional copy
			go handleTunnel(localConn, remoteConn)
		}
	}()

	// Step 3: Create PostgreSQL connection string
	// Note: We connect to local port that's being forwarded
	connStr := fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=require",
		"127.0.0.1", localAddr.Port, dbConfig.User, dbConfig.Password, dbConfig.DBName,
	)

	// Step 4: Connect to PostgreSQL
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %v", err)
	}

	// Test the connection
	err = db.Ping()
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to ping database: %v", err)
	}
	return db, nil
}

// handleTunnel copies data between local and remote connections
func handleTunnel(local, remote net.Conn) {
	defer local.Close()
	defer remote.Close()

	// Copy remote -> local
	go func() {
		_, err := io.Copy(local, remote)
		if err != nil {
			fmt.Printf("Error copying remote->local: %v\n", err)
		}
	}()

	// Copy local -> remote
	_, err := io.Copy(remote, local)
	if err != nil {
		fmt.Printf("Error copying local->remote: %v\n", err)
	}
}
