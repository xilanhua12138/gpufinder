import subprocess
import time
import requests
import json
from datetime import datetime, time as dt_time

# 飞书 Webhook URL
FEISHU_WEBHOOK_URL = "https://www.feishu.cn/flow/api/trigger-webhook/37143a0ac16c1e65385d8aad7f2f1652"

def get_disk_usage():
    try:
        output = subprocess.check_output(f"ssh u7 'df -h | grep -E \"/mnt$|/mnt2$|/mnt3$|/mnt6$\"'", shell=True).decode()
        disk_info = []
        for line in output.strip().split("\n"):
            parts = line.split()
            filesystem = parts[0]
            size = parts[1]
            used = parts[2]
            available = parts[3]
            usage_percent = parts[4]
            mount_point = parts[5]
            disk_info.append({
                "filesystem": filesystem,
                "size": size,
                "used": used,
                "available": available,
                "usage_percent": usage_percent,
                "mount_point": mount_point
            })
        return disk_info
    except subprocess.CalledProcessError:
        print("无法获取磁盘使用情况")
        return None

def send_feishu_message(message):
    headers = {
        "Content-Type": "application/json"
    }
    payload = {
        "msg_type": "text",
        "content": message
    }
    response = requests.post(FEISHU_WEBHOOK_URL, headers=headers, data=json.dumps(payload))
    if response.status_code != 200:
        print(f"发送飞书消息失败: {response.text}")

def main():
    last_report_time = 0
    while True:
        current_time = time.time()
        if current_time - last_report_time >= 24 * 60 * 60:  # 每1小时检查一次
            disk_info = get_disk_usage()
            if disk_info:
                message = f"磁盘使用情况报告 (/mnt, /mnt2, /mnt3, /mnt6):\n\n"
                for disk in disk_info:
                    message += (f"挂载点: {disk['mount_point']}\n"
                                f"总大小: {disk['size']}, 已使用: {disk['used']}, 可用: {disk['available']}, 使用率: {disk['usage_percent']}\n\n")
                message += f"报告时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                send_feishu_message(message)
                last_report_time = current_time
        
        time.sleep(60)  # 每分钟检查一次

if __name__ == "__main__":
    main()