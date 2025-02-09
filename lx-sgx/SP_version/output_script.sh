#!/bin/bash

# 文件夹名字
time="07-24_22-53-31"

# 结果文件名
result_file="result_$time.txt"

# 删除文件（如果存在）
if [ -e "$result_file" ]; then
    rm ./output/"$result_file"
fi

touch ./output/"$result_file"
chmod +w ./output/"$result_file"

# 遍历所有txt文件
for file in ./output/$time/*.txt; do
  # 提取文件名和扩展名
  filename=${file%.*}
  extension=${file##*.}
  # 取得目标行的时间信息，并写入结果文件
  number=$(basename "$filename" | cut -d '_' -f 2) # 获取文件名中的第二个字段  循环次数
  cpu_number=$(basename "$filename" | cut -d '_' -f 3 | cut -d ',' -f 1) # 获取文件名中的第三个字段，并切掉逗号之后的部分 内核数
  wait_time=$(grep -Po '(?<=多线程平均等待耗时:)[\d\.]+' "$file")
  total_time=$(grep -Po '(?<=总耗时:)[\d\.]+' "$file")
  echo "$number,$cpu_number,$wait_time,$total_time" >> ./output/"$result_file"
done

