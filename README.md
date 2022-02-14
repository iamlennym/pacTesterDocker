
# pacTesterDocker
Dockerized version of pactester (https://github.com/manugarg/pacparser)

## Steps Required ##

* Clone the repository onto your Mac / Linux machine (e.g. `git clone https://github.com/iamlennym/pacTesterDocker.git`).
* Build the `pactester` docker image:
    - Execute the following commands:
        - `./build.sh` (builds a local docker image for `pactester`)
        - `docker images` (Lists local images. Be sure that `pactester` is in the list)

            Example output:
            ```
            REPOSITORY          TAG               IMAGE ID       CREATED         SIZE
            pactester           latest            c2c1764cc01a   26 minutes ago  3.12MB
            ```
* Add the *pactester.sh* script to your PATH. 
  * Although you can execute the script from the build directory directly, it is convenient to also add the path to the script to your environment's PATH. 


## Example Usage ##

* The `pactester` usage screen is displayed when no parameters are specified:

```
            Usage:  /app/pactester <-p pacfile> <-u url> [-h host] [-c client_ip] [-e]
                    /app/pactester <-p pacfile> <-f urlslist> [-c client_ip] [-e]

            Options:
            -p pacfile   : PAC file to test (specify '-' to read from standard input)
            -u url       : URL to test for
            -h host      : Host part of the URL
            -c client_ip : client IP address (as returned by myIpAddres() function
                            in PAC files), defaults to IP address on which it is running.
            -e           : Deprecated: IPv6 extensions are enabledby default now.
            -f urlslist  : a file containing list of URLs to be tested.
            -v           : print version and exit
```

* Test and verify a pacfile `sample.pac`:
  * pactester.sh -p sample.pac -u http://www.example.com

        Output:
        PROXY ${GATEWAY}:9400; PROXY ${SECONDARY_GATEWAY}:9400; PROXY ${GATEWAY}:80; PROXY ${SECONDARY_GATEWAY}:80; DIRECT