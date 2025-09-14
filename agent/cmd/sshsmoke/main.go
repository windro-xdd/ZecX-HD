package main

import (
    "bufio"
    "fmt"
    "log"
    "os"
    "time"
    gossh "golang.org/x/crypto/ssh"
)

func main() {
    addr := env("ADDR", "127.0.0.1:22")
    user := env("USER", "test")
    pass := env("PASS", "test")

    cfg := &gossh.ClientConfig{
        User:            user,
        Auth:            []gossh.AuthMethod{gossh.Password(pass)},
        HostKeyCallback: gossh.InsecureIgnoreHostKey(),
        Timeout:         5 * time.Second,
    }
    conn, err := gossh.Dial("tcp", addr, cfg)
    if err != nil { log.Fatalf("dial: %v", err) }
    defer conn.Close()

    sess, err := conn.NewSession()
    if err != nil { log.Fatalf("session: %v", err) }
    defer sess.Close()

    // Request PTY and start shell
    if err := sess.RequestPty("xterm", 80, 24, gossh.TerminalModes{}); err != nil {
        log.Fatalf("pty: %v", err)
    }
    stdout, _ := sess.StdoutPipe()
    stdin, _ := sess.StdinPipe()
    if err := sess.Shell(); err != nil { log.Fatalf("shell: %v", err) }

    // Read asynchronously
    done := make(chan struct{})
    go func() {
        r := bufio.NewScanner(stdout)
        for r.Scan() { fmt.Println(r.Text()) }
        close(done)
    }()

    // Send commands (add pwd and ls as requested)
    cmds := []string{"pwd", "ls -la", "whoami", "id", "uname -a", "exit"}
    for _, c := range cmds {
        _, _ = fmt.Fprintf(stdin, "%s\n", c)
        time.Sleep(300 * time.Millisecond)
    }
    <-done
}

func env(k, def string) string { if v := os.Getenv(k); v != "" { return v }; return def }
