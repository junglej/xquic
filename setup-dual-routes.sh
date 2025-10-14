#!/bin/bash

# 清除旧规则（可选）
ip rule del from 192.168.0.111 table wlp1s0_table 2>/dev/null
ip rule del from 192.168.0.110 table wlp3s0_table 2>/dev/null
ip route flush table wlp1s0_table 2>/dev/null
ip route flush table wlp3s0_table 2>/dev/null

# wlp1s0 路由表配置
ip route add 192.168.0.0/24 dev wlp1s0 src 192.168.0.111 table wlp1s0_table
ip route add default via 192.168.0.1 dev wlp1s0 table wlp1s0_table

# wlp3s0 路由表配置
ip route add 192.168.0.0/24 dev wlp3s0 src 192.168.0.110 table wlp3s0_table
ip route add default via 192.168.0.1 dev wlp3s0 table wlp3s0_table

# 策略路由规则
ip rule add from 192.168.0.111 table wlp1s0_table priority 100
ip rule add from 192.168.0.110 table wlp3s0_table priority 101

# 主路由表（默认使用其中一张网卡）
ip route add default via 192.168.0.1 dev wlp1s0 metric 100

echo "双网卡路由配置完成"