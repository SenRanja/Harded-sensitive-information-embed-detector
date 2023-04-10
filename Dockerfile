FROM amd64/alpine:3.14

RUN apk update && apk add git && apk add tzdata && cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime && echo "Asia/Shanghai" > /etc/timezone && apk del tzdata

ADD ./SecretDetectionDir /secretDetection/

WORKDIR /secretDetection

EXPOSE 8000

ENTRYPOINT ["/secretDetection/http"]
