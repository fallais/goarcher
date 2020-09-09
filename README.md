# goarcher

**goarcher** is a library written in Golang that helps you with the **RSA Archer REST API**.

## Usage

```go
import "github.com/fallais/goarcher"
```

Construct a new RSA client, then use the various services on the client to access different parts of the RSA Archer API. For example:

```go
client := goarcher.NewClient(nil)
```

If you want to provide your own `http.Client`, you can do it :

```go
httpClient := &http.Client{}
client := goarcher.NewClient(httpClient)
```
