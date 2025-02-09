#!/bin/bash

num_tasks=("50" "100")
cpu_numbers=("1" "3" "6" "12")

# 定义参数组合
config=()

for num_thread in "${num_tasks[@]}"
do
    for cpu_number in "${cpu_numbers[@]}"
    do
        config+=("$num_thread $cpu_number")
    done
done

# 编译程序
make clean
source /opt/intel/sgxsdk/environment
make SGX_MODE=SIM
# make

# 获取时间
timestamp=$(date +"%m-%d_%H-%M-%S")

# 遍历参数组合，并执行程序
for param in "${config[@]}"
do
    # 解构参数
    read -ra params <<<"$param"
    num_tasks="${params[0]}"
    cpu_number="${params[1]}"
    filename="output_${num_tasks}_${cpu_number}.txt" #文件名字
    mkdir -p "./output/${timestamp}"  # 创建 output 目录，如果不存在的话
    echo "Executing program with num_tasks=$num_tasks, cpu_number=$cpu_number"
    # 运行程序，并传递变量作为命令行参数,并记录在文件里面
    ./app "$num_tasks" "$cpu_number" > "./output/${timestamp}/$filename"
done

# 清除程序
make clean

