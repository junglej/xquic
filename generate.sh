#!/bin/bash

# XQUIC Demo 上行测试环境准备脚本 (Linux)
# 使用方法: ./setup_upload_test.sh

set -e

echo "======================================"
echo "XQUIC Upload Test Environment Setup"
echo "======================================"

# 配置变量
BUILD_DIR="${BUILD_DIR:-./build}"
CLIENT_FILES_DIR="${BUILD_DIR}/client_files"  # 客户端要上传的文件
SERVER_RECV_DIR="${BUILD_DIR}/server_recv"    # 服务器接收文件的目录
LOGS_DIR="${BUILD_DIR}/logs"

# 1. 检查编译产物
echo ""
echo "[1/5] Checking build artifacts..."
if [ ! -f "${BUILD_DIR}/demo/demo_server" ]; then
    echo "Error: demo_server not found!"
    echo "Please compile xquic first:"
    echo "  cd ~/xquic && mkdir build && cd build"
    echo "  cmake .. && make -j\$(nproc)"
    exit 1
fi

if [ ! -f "${BUILD_DIR}/demo/demo_client" ]; then
    echo "Error: demo_client not found!"
    exit 1
fi

echo "✓ Build artifacts found"

# 2. 创建目录结构
echo ""
echo "[2/5] Creating directory structure..."
mkdir -p ${CLIENT_FILES_DIR}
mkdir -p ${SERVER_RECV_DIR}
mkdir -p ${LOGS_DIR}
echo "✓ Directories created:"
echo "  - ${CLIENT_FILES_DIR}  (files to upload)"
echo "  - ${SERVER_RECV_DIR}   (received files on server)"
echo "  - ${LOGS_DIR}          (log files)"

# 3. 生成客户端测试文件（要上传的）
echo ""
echo "[3/5] Generating upload test files..."

generate_file() {
    local size=$1
    local unit=$2
    local filename=$3
    
    if [ -f "${CLIENT_FILES_DIR}/${filename}" ]; then
        echo "  - ${filename} already exists, skipping"
    else
        echo "  - Generating ${filename} (${size}${unit})..."
        if [ "$unit" = "K" ]; then
            dd if=/dev/urandom of="${CLIENT_FILES_DIR}/${filename}" bs=1024 count=${size} status=none
        elif [ "$unit" = "M" ]; then
            dd if=/dev/urandom of="${CLIENT_FILES_DIR}/${filename}" bs=1048576 count=${size} status=none
        elif [ "$unit" = "G" ]; then
            dd if=/dev/urandom of="${CLIENT_FILES_DIR}/${filename}" bs=1048576 count=$((size * 1024)) status=none
        fi
        # 计算MD5用于验证
        md5sum "${CLIENT_FILES_DIR}/${filename}" | awk '{print $1}' > "${CLIENT_FILES_DIR}/${filename}.md5"
    fi
}

# 小文件 - 用于快速测试上行连通性
generate_file 1 K "upload_1KB.dat"
generate_file 10 K "upload_10KB.dat"
generate_file 100 K "upload_100KB.dat"

# 中等文件 - 用于基础上行性能测试
generate_file 1 M "upload_1MB.dat"
generate_file 10 M "upload_10MB.dat"

# 大文件 - 用于上行吞吐量测试
generate_file 100 M "upload_100MB.dat"
generate_file 500 M "upload_500MB.dat"
