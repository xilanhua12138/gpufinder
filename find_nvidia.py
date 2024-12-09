import subprocess
import time
import requests
import json
from datetime import datetime, time as dt_time

# 飞书 Webhook URL
FEISHU_WEBHOOK_URL = "https://www.feishu.cn/flow/api/trigger-webhook/37143a0ac16c1e65385d8aad7f2f1652"
def get_hosts():
    try:
        output = subprocess.check_output("grep '^Host ' ~/.ssh/config | awk '{print $2}'", shell=True).decode().strip()
        return output.split('\n')
    except:
        print("无法读取 SSH 配置文件")
        return []

def get_gpu_info(host):
    try:
        output = subprocess.check_output(f"ssh {host} 'nvidia-smi --query-gpu=index,memory.used,memory.total,utilization.gpu,temperature.gpu --format=csv,nounits,noheader'", shell=True).decode()
        gpu_info = []
        for line in output.strip().split("\n"):
            index, mem_used, mem_total, gpu_util, temp = map(float, line.split(","))
            mem_usage_percent = (mem_used / mem_total) * 100
            gpu_info.append({
                "index": int(index),
                "mem_usage_percent": mem_usage_percent,
                "mem_used": mem_used,
                "mem_total": mem_total,
                "gpu_util": gpu_util,
                "temperature": temp
            })
        return gpu_info
    except:
        print(f"{host} 无法连接或没有 nvidia-smi")
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

def is_working_hours():
    now = datetime.now().time()
    start = dt_time(9, 0)  # 上午 9:00
    end = dt_time(22, 0)   # 下午 10:00
    return start <= now <= end

def main():
    hosts = get_hosts()
    last_report_time = time.time()
    idle_gpu_tracker = {}  # 新增：用于跟踪GPU空闲状态的字典
    
    while True:
        if is_working_hours():
            idle_gpus = {}
            for host in hosts:
                gpu_info = get_gpu_info(host)
                if gpu_info:
                    current_time = time.time()
                    for gpu in gpu_info:
                        gpu_key = f"{host}_gpu{gpu['index']}"
                        if gpu["mem_used"] < 20:
                            if gpu_key not in idle_gpu_tracker:
                                idle_gpu_tracker[gpu_key] = current_time
                            elif current_time - idle_gpu_tracker[gpu_key] >= 300:  # 5分钟 = 300秒
                                if host not in idle_gpus:
                                    idle_gpus[host] = []
                                idle_gpus[host].append(gpu)
                        else:
                            idle_gpu_tracker.pop(gpu_key, None)
            
            if idle_gpus and (current_time - last_report_time >= 60*40):  # 每40分钟检查一次
                message = f"发现持续5分钟以上空闲的显卡 (GPU显存使用 < 20%):\n\n"
                for host, gpus in idle_gpus.items():
                    if host[0] != 'u':
                        continue
                    if 'u1' in host or 'u2' in host or 'u3' in host or 'u4' in host or 'u5' in host:
                        continue
                    message += f"主机: {host}\n"
                    for gpu in gpus:
                        message += f"""  GPU {gpu['index']}: 使用率: {gpu['gpu_util']:.2f}%, 显存使用: {gpu['mem_used']:.0f}MB / {gpu['mem_total']:.0f}MB ({gpu['mem_usage_percent']:.2f}%), 温度: {gpu['temperature']:.1f}°C\n"""
                    message += "\n"
                message += f"报告时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                
                send_feishu_message(message)
                last_report_time = current_time
        
        time.sleep(60)  # 每分钟检查一次

if __name__ == "__main__":
    main()