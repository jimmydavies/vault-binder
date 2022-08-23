package main

import (
    "fmt"
    "encoding/json"
    "strings"
    "os"
    "io/ioutil"
    vault "github.com/hashicorp/vault/api"
    auth "github.com/hashicorp/vault/api/auth/aws"
    "log"
    "os/exec"
    "context"
)

type secretfield []string

func (sf *secretfield) UnmarshalJSON(data []byte) error {
    var s string
    if err := json.Unmarshal(data, &s); err != nil {
        return err
    }
    *sf = strings.Split(s, ":")
    return nil
}

type Bindings map[string]secretfield

func main() {
    // Open our jsonFile
    jsonFile, err := os.Open("./secret_bindings.json")
    // if we os.Open returns an error then handle it
    if err != nil {
        fmt.Println(err)
    }
    fmt.Println("Successfully Opened users.json")
    // defer the closing of our jsonFile so that we can parse it later on
    defer jsonFile.Close()

    byteValue, _ := ioutil.ReadAll(jsonFile)

    // we initialize our Users array
    var bindings Bindings

    // we unmarshal our byteArray which contains our
    // jsonFile's content into 'users' which we defined above
    json.Unmarshal(byteValue, &bindings)

    // we iterate through every user within our users array and
    // print out the user Type, their name, and their facebook url
    // as just an example

    config := vault.DefaultConfig()

    client, err := vault.NewClient(config)
    if err != nil {
        log.Fatalf("unable to initialize Vault client: %v", err)
    }

    if _, present := os.LookupEnv("VAULT_TOKEN"); !present {
        buf, err := os.ReadFile("/root/vault/.vault-token-ansible-"+ os.Getenv("ENV") + "-nonce")
        nonce := string(buf)
        fmt.Println(nonce)
        awsAuth, err := auth.NewAWSAuth(
            auth.WithRole("ansible"), // if not provided, Vault will fall back on looking for a role with the IAM role name if you're using the iam auth type, or the EC2 instance's AMI id if using the ec2 auth type
            auth.WithEC2Auth(),
            auth.WithPKCS7Signature(),
            auth.WithNonce(nonce),
        )
        if err != nil {
            log.Fatalf("unable to initialize AWS auth method: %w", err)
        }

        authInfo, err := client.Auth().Login(context.TODO(), awsAuth)
        if err != nil {
            log.Fatalf("unable to login to AWS auth method: %w", err)
        }
        if authInfo == nil {
            log.Fatalf("no auth info was returned after login")
        }

        fmt.Println(authInfo.Auth.LeaseDuration)
    }

    for key, element := range bindings {
        // Reading a secret

        if _, present := os.LookupEnv(key); present {
            continue
        }

        secret, err := client.Logical().Read(element[0])
        if err != nil {
            log.Fatalf("unable to read secret: %v", err)
        }

        value, ok := secret.Data[element[1]].(string)
        if !ok {
            log.Fatalf("value type assertion failed: %T %#v", secret.Data[element[1]], value)
        }

        os.Setenv(key, value)
    }

    cmd := exec.Command(os.Args[1], os.Args[2:]...)
    cmd.Env = os.Environ()
    cmd.Stdout = os.Stdout
    cmd.Stderr = os.Stderr
    err = cmd.Run()
    if err != nil {
        log.Fatalf("cmd.Run() failed with %s\n", err)
    }

}
