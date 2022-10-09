FROM amd64/alpine:3.14

ADD ./GitleaksDir /webscan/

RUN apk update && apk add git

WORKDIR /webscan

EXPOSE 8000

ENTRYPOINT ["/webscan/http"]
