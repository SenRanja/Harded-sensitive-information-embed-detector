#!/bin/bash

echo "开始运行$0" `date "+%H:%M:%S"`
for file in /var/GitCloneTest/*
do 
    echo "开始时间" `date "+%H:%M:%S"`
    echo "扫描地址: $file"
    if test -d $file
    then
        /home/syj/SecretDetection detect --no-git -s $file -f csv -r /home/syj/shenyanjian/$(basename $file)-WithoutGit.csv
    fi
    echo "结束时间" `date "+%H:%M:%S"`
done

echo "结束运行$0" `date "+%H:%M:%S"`