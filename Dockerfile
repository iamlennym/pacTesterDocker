FROM alpine as builder

RUN apk update && apk add ca-certificates openssl

ARG cert_location=/usr/local/share/ca-certificates

# Get certificate from "github.com"
RUN openssl s_client -showcerts -connect github.com:443 </dev/null 2>/dev/null|openssl x509 -outform PEM > ${cert_location}/github.crt
# Get certificate from "proxy.golang.org"
RUN openssl s_client -showcerts -connect proxy.golang.org:443 </dev/null 2>/dev/null|openssl x509 -outform PEM >  ${cert_location}/proxy.golang.crt
# Update certificates
RUN update-ca-certificates

RUN mkdir /pacBuilder 
WORKDIR /pacBuilder 

RUN apk update
RUN apk add git
RUN apk add make
RUN apk add bash
RUN apk add gcc
RUN apk add musl-dev
RUN git clone https://github.com/manugarg/pacparser.git
WORKDIR /pacBuilder/pacparser/src
RUN sed -i 's/__va_copy/va_copy/g' Makefile
# RUN sed -i 's/FLAGS) pactester.c/FLAGS) -static pactester.c/g' src/Makefile
RUN make 
RUN rm pactester
RUN ar rcs libpacparser.a pacparser.o
RUN cc -g -DXP_UNIX -Wall -DVERSION=1.3.7rc6-32-g962e64e -Ispidermonkey/js/src  pactester.c -static -o pactester -lpacparser -ljs -L. -I.

FROM scratch
COPY --from=builder /pacBuilder/pacparser/src/pactester /app/
WORKDIR /workspace
CMD ["/app/pactester"]

