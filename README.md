A Kubernetes [client-go credentials plugin](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#client-go-credential-plugins) to fetch TLS credentials from an ACME server

Standalone example of its usage against the letsencrypt [pebble](https://github.com/letsencrypt/pebble) server:

a. Start pebble:
```
[mrogers@mothra bin]$ cd ../src/github.com/letsencrypt/pebble/
[mrogers@mothra pebble]$ ../../../../bin/pebble
Pebble 2018/07/09 11:46:34 Generated new root issuer with serial 1a80b8d10aa84321
Pebble 2018/07/09 11:46:34 Generated new intermediate issuer with serial 7289c00b2a19a780
Pebble 2018/07/09 11:46:34 Configured to reject 15% of good nonces
Pebble 2018/07/09 11:46:34 Pebble running, listening on: 127.0.0.1:14000
```

b. Run the plugin:
```
[mrogers@mothra acme-exec-plugin]$ go build -o acme-exec-plugin
[mrogers@mothra acme-exec-plugin]$ ./acme-exec-plugin --server-url=https://127.0.0.1:14000 --server-ca=pebble.minica.pem --challenge-addr=localhost:5002 --email=foo@bar.com --write-client-key=true --subject='CN=localhost' --names=localhost
{"kind":"ExecCredential","apiVersion":"client.authentication.k8s.io/v1alpha1","spec":{},"status":{"clientCertificateData":"-----BEGIN CERTIFICATE-----\nMIIDEzCCAfugAwIBAgIIPA/fKjaNrrkwDQYJKoZIhvcNAQELBQAwKDEmMCQGA1UE\nAxMdUGViYmxlIEludGVybWVkaWF0ZSBDQSA3Mjg5YzAwHhcNMTgwNzA5MTU1MjM3\nWhcNMjMwNzA5MTU1MjM3WjAUMRIwEAYDVQQDEwlsb2NhbGhvc3QwggEiMA0GCSqG\nSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC3PHCk1GC9WbP+D8c5vfJTO1Y8cD0SQWLH\nL37KE611teS5Hd4P7/ooXQYn6UPy9xk7+wsMMAZG2z8Z1WKmwL8DiW5vQvgIngmk\nuVnh2SsZIxn6fy22/QiF0k8X9ovITJjYfarjIAQb0VmxnAppyV7CZHtJz5lE5K8A\nGfThcIxl7eqxAZBDhERRO/h3MZGB2PIOhLLUT7u7+TA7j7J7RMk4TLUeEJYE3yzp\nx4hIEb41tpsL9/VNwuAcxn6T49xANDyBlRzyjkMP3IKeSo3dxUWbBu20p4neGUxI\ny0JdgMZ4xEKXWWmcMMkSOEmVufnV8bKHLu/VNeZv7XDWtFKBRgRxAgMBAAGjVTBT\nMA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIw\nDAYDVR0TAQH/BAIwADAUBgNVHREEDTALgglsb2NhbGhvc3QwDQYJKoZIhvcNAQEL\nBQADggEBAAEtcr230xfE8wAKJKuwBt06RIyjIV65vos1U2QpCyvShAHNP7fogC9o\nd3wXjHw+zE1Tua3IweBda1KzGiyVtoegUl2XTr0Bsx3H7Isjg3nxQawAT56/awUv\nesSfb4zY8/d1SZu8XhI8+t8KZ1m24CM2gUElCkoPcuPIysOWzAuUxhq/4MpGSCXD\noYA63lDSIAYWoDIirCEZ/7rl3bO8vvvwv827IjFiiyCp97mUaBsrp4uVj4JaqpNR\nBOrqTjj7yioFxMpuZ5YubUw/TsoHM6zLKogC7+u7yTccNTg8M55AvfytkVuByCr2\n7vKNtg9U3WAF7z/cihJjv96quHt9ndk=\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIDFDCCAfygAwIBAgIIconACyoZp4AwDQYJKoZIhvcNAQELBQAwKDEmMCQGA1UE\nAxMdUGViYmxlIEludGVybWVkaWF0ZSBDQSA3Mjg5YzAwHhcNMTgwNzA5MTU0NjM0\nWhcNNDgwNzA5MTY0NjM0WjAoMSYwJAYDVQQDEx1QZWJibGUgSW50ZXJtZWRpYXRl\nIENBIDcyODljMDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALTsm0FC\nPcDy8YiuwvwRuDG20sRRXrFKSNXwwbhWiSlDjulzbujCb29B6mQC1fvP3dG/xSYY\nOw8xho+fnbnN1DSQU7wcnT54i6M3Lamu2I7Nubxu7knkGYMSMv/6IwjvjD4kyO95\nufcUC90zMLu9eJ+ZkeMQ/Aqv/wRDudAdqmOPnU4vfQH0jThPgD2PrDK3UU7PZJ8P\nn+EVIu5xOvPnnd+Kq5lvRs8+dXWPXM0zPMUAiW4kKoHVHtlTmr8k/Vxi8nQQszlC\nS4qjiv/XhewtxcH269CcvNbDHj8AGX6kCjmDmXdCMTtvGoJnqwG8urj+4hG/fWs7\nUpcYZiCfFdIz0fsCAwEAAaNCMEAwDgYDVR0PAQH/BAQDAgKEMB0GA1UdJQQWMBQG\nCCsGAQUFBwMBBggrBgEFBQcDAjAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEB\nCwUAA4IBAQBn2J8l0iQuPOKov2/6uBtxRDbWUQqHv+c0+JkOn2pm0sih79ARDRco\nctUcRKVXTceH4jo4wUSyW/vNRy0nw2YrYVBD8USeJcbO8ihoyHU3kaSVp+Vw87sK\n9gnySkKk4JESlkDTYE4Y1j6Mgd2SRRuWbCTAR8/GLJC3m0t6rCN1W6n7C/aP5uXl\ngI0XD45itrOjhgq/r+av5zWqYoCV6jnf9NSBTgmC4gnm3UGnK3RBEOML36RskKhi\nCipZQvOI1v67TfelKasaSnhXEpuM5fRuVLl9n7of5cwmJRpyqgAajlY1UZus1N8L\nftHPdQ6bU52FdehKSFexVxPg3vko0AUa\n-----END CERTIFICATE-----\n","clientKeyData":"-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAtzxwpNRgvVmz/g/HOb3yUztWPHA9EkFixy9+yhOtdbXkuR3e\nD+/6KF0GJ+lD8vcZO/sLDDAGRts/GdVipsC/A4lub0L4CJ4JpLlZ4dkrGSMZ+n8t\ntv0IhdJPF/aLyEyY2H2q4yAEG9FZsZwKaclewmR7Sc+ZROSvABn04XCMZe3qsQGQ\nQ4REUTv4dzGRgdjyDoSy1E+7u/kwO4+ye0TJOEy1HhCWBN8s6ceISBG+NbabC/f1\nTcLgHMZ+k+PcQDQ8gZUc8o5DD9yCnkqN3cVFmwbttKeJ3hlMSMtCXYDGeMRCl1lp\nnDDJEjhJlbn51fGyhy7v1TXmb+1w1rRSgUYEcQIDAQABAoIBAHIZP6dT291sgykb\n2Bm7jq6HT16ZIV5Buul/SLs6X5PhrMgcsg9IhoQl0NR/a2Favqrb2vg+21m54mQK\nvMBLW2YvaMX9dIehKS4agL6ixTSE6ANUuDmu/GSgHcI1MruJ/s8oCYYehJBx3yE6\noj1XOBtiCGdgzvbYU6SDhTnwJGy/F2dkgIysnkPc/BPSVrsbnQ+QYGr8tHqkSzl/\nNqClA4JworpTBtun2TOVPmO7rppOmNGxe+Z0Z0RrwC/hk0oECw5569Ner2vo3nRC\nCQVTJZYsq/s1EH8ra+utJB/Kihs1PeGLv8U+8OTy0xUddFdEvp1/U9beO8qYTPq2\n3ffaIgECgYEAwyTwm9z6dxc/rOvOIjGErVuX/juXf8ifaDFXAsYgXxU1VruXeWoU\nhfd5ZEExbbnGeb81FnwDalgxf4Hr8FyrxEmjrHd3XzPIUu0iS6wB/qxr/3GFXzjW\nRiX/Yt2i5p3wTSeyLi0E1cTlhIBTE/31R+ZU6A7RY74YipGUJ5vrWNECgYEA8GDT\nf0rve6919naaWkIkusOqNEPTHi0YpGDmltRKYoZhpDYJKqorO+yc2yiLLGUYp1eZ\nafHyKUMPiCPq10WHn02ZHKN/aG6kcNmlsB9U0GymRYQSlGizmdYIIK8XyET5LTfW\nWP5GqrD5Q8Nz5i8mipHPICUUJ2cmRVht1LLa2aECgYEAnaKdaoqbGNCC82CYZy6x\nCojOwuPIgcTCYBxbOTZqt+Qd7i4jMkTqxz0dpkqzbvt+xKIcdElBSQptEZ8VxFhX\nuHvz50GqABGIZNSBu7b69Yq6wuIk5sK29HuFTYvUJ461qt3CJWLgYP5omRxAAApJ\ntQbu13YA1x2cHXNzxntBJcECgYB0OOyppEqsS8bGVswEjeyCXK6DvLNr6LP8blmv\nXY9lmcHGCtZdyY9D1wB0OmMoIO1No94qSnAioSj2Ux9t3FFZpcQ9A5RLowthAOrK\ngCua5p1yCQyOsxz7aW/elanzC95Kja/WsYLrbsvmhq8YAX4qC5vQ1/ypnIb1im74\nI04LYQKBgQCWxqZeVGyhAeKctrakY29ItkDPLAdeHj/joSoD22Dzv9MmVvMOyiNj\nwER9Dz3/DECPGtOr0KdqO7PfriDvId9mH0FXMwwSM9LmlquuJ32MI4Hoa5K8uAL/\nnEFGcAU3N9ZQm4TWgxml3N0mFgsZDYQvBxGoNLFw9HW4+p011NjgaQ==\n-----END RSA PRIVATE KEY-----\n"}}
```

c. Pebble output:
```
Pebble 2018/07/09 11:52:26 GET /dir -> calling handler()
Pebble 2018/07/09 11:52:26 GET /nonce-plz -> calling handler()
Pebble 2018/07/09 11:52:26 GET /nonce-plz -> calling handler()
Pebble 2018/07/09 11:52:26 POST /sign-me-up -> calling handler()
Pebble 2018/07/09 11:52:26 There are now 1 accounts in memory
Pebble 2018/07/09 11:52:26 GET /nonce-plz -> calling handler()
Pebble 2018/07/09 11:52:26 POST /order-plz -> calling handler()
Pebble 2018/07/09 11:52:26 There are now 1 authorizations in the db
Pebble 2018/07/09 11:52:26 Added order "HV39CnKINbWgXC2N2vwcvOA7T0QwYq4l-1csJYdph8o" to the db
Pebble 2018/07/09 11:52:26 There are now 1 orders in the db
Pebble 2018/07/09 11:52:26 GET /authZ/YA1PwEXd2wj-Se563934AUiFg4SJSqUelH1RBXzD_xg -> calling handler()
Pebble 2018/07/09 11:52:26 GET /nonce-plz -> calling handler()
Pebble 2018/07/09 11:52:26 POST /chalZ/GMsjYyLy5VX04q8QovNIIEIIcUXtt-s_1PQBlAtHYRg -> calling handler()
Pebble 2018/07/09 11:52:26 Pulled a task from the Tasks queue: &va.vaTask{Identifier:"localhost", Challenge:(*core.Challenge)(0xc4204c00a0), Account:(*core.Account)(0xc4201381e0)}
Pebble 2018/07/09 11:52:26 Starting 3 validations.
Pebble 2018/07/09 11:52:26 Sleeping for 10s seconds before validating
Pebble 2018/07/09 11:52:26 Sleeping for 3s seconds before validating
Pebble 2018/07/09 11:52:26 Sleeping for 5s seconds before validating
Pebble 2018/07/09 11:52:27 GET /chalZ/GMsjYyLy5VX04q8QovNIIEIIcUXtt-s_1PQBlAtHYRg -> calling handler()
Pebble 2018/07/09 11:52:28 GET /chalZ/GMsjYyLy5VX04q8QovNIIEIIcUXtt-s_1PQBlAtHYRg -> calling handler()
Pebble 2018/07/09 11:52:29 Attempting to validate w/ HTTP: http://localhost:5002/.well-known/acme-challenge/2EzkGYD3fC5zNq07k3CHECwFmBx7SoXjEhyrpt_fCc0
Pebble 2018/07/09 11:52:29 GET /chalZ/GMsjYyLy5VX04q8QovNIIEIIcUXtt-s_1PQBlAtHYRg -> calling handler()
Pebble 2018/07/09 11:52:30 GET /chalZ/GMsjYyLy5VX04q8QovNIIEIIcUXtt-s_1PQBlAtHYRg -> calling handler()
Pebble 2018/07/09 11:52:31 Attempting to validate w/ HTTP: http://localhost:5002/.well-known/acme-challenge/2EzkGYD3fC5zNq07k3CHECwFmBx7SoXjEhyrpt_fCc0
Pebble 2018/07/09 11:52:31 GET /chalZ/GMsjYyLy5VX04q8QovNIIEIIcUXtt-s_1PQBlAtHYRg -> calling handler()
Pebble 2018/07/09 11:52:32 GET /chalZ/GMsjYyLy5VX04q8QovNIIEIIcUXtt-s_1PQBlAtHYRg -> calling handler()
Pebble 2018/07/09 11:52:33 GET /chalZ/GMsjYyLy5VX04q8QovNIIEIIcUXtt-s_1PQBlAtHYRg -> calling handler()
Pebble 2018/07/09 11:52:34 GET /chalZ/GMsjYyLy5VX04q8QovNIIEIIcUXtt-s_1PQBlAtHYRg -> calling handler()
Pebble 2018/07/09 11:52:35 GET /chalZ/GMsjYyLy5VX04q8QovNIIEIIcUXtt-s_1PQBlAtHYRg -> calling handler()
Pebble 2018/07/09 11:52:36 Attempting to validate w/ HTTP: http://localhost:5002/.well-known/acme-challenge/2EzkGYD3fC5zNq07k3CHECwFmBx7SoXjEhyrpt_fCc0
Pebble 2018/07/09 11:52:36 GET /chalZ/GMsjYyLy5VX04q8QovNIIEIIcUXtt-s_1PQBlAtHYRg -> calling handler()
Pebble 2018/07/09 11:52:36 authz YA1PwEXd2wj-Se563934AUiFg4SJSqUelH1RBXzD_xg set VALID by completed challenge GMsjYyLy5VX04q8QovNIIEIIcUXtt-s_1PQBlAtHYRg
Pebble 2018/07/09 11:52:37 GET /chalZ/GMsjYyLy5VX04q8QovNIIEIIcUXtt-s_1PQBlAtHYRg -> calling handler()
Pebble 2018/07/09 11:52:37 GET /nonce-plz -> calling handler()
Pebble 2018/07/09 11:52:37 POST /finalize-order/HV39CnKINbWgXC2N2vwcvOA7T0QwYq4l-1csJYdph8o -> calling handler()
Pebble 2018/07/09 11:52:37 Order HV39CnKINbWgXC2N2vwcvOA7T0QwYq4l-1csJYdph8o is fully authorized. Processing finalization
Pebble 2018/07/09 11:52:37 Issued certificate serial 3c0fdf2a368daeb9 for order HV39CnKINbWgXC2N2vwcvOA7T0QwYq4l-1csJYdph8o
Pebble 2018/07/09 11:52:38 GET /my-order/HV39CnKINbWgXC2N2vwcvOA7T0QwYq4l-1csJYdph8o -> calling handler()
Pebble 2018/07/09 11:52:39 GET /certZ/3c0fdf2a368daeb9 -> calling handler()

```

For an example of using the plugin binary as a client-go exec plugin, see [example.kubeconfig](https://raw.githubusercontent.com/mrogers950/acme-exec-plugin/master/example.kubeconfig)
