#!/bin/bash
ssh -t takondwa@192.168.1.10 "sudo tc qdisc del dev eth0 root"
