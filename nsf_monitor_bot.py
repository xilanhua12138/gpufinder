import subprocess
import os
import requests
import json
import logging
from flask import Flask, request, jsonify, make_response
import paramiko
from paramiko import SSHConfig
from functools import lru_cache, wraps
import time
import socket
from multiprocessing import Pool

app = Flask(__name__)
app.config['JSON_AS_ASCII'] = False  # 确保正确处理非ASCII字符
app.config['JSONIFY_MIMETYPE'] = "application/json; charset=utf-8"  # 设置JSON响应的MIME类型为UTF-8

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

APP_ID = "cli_a67cd6b048389013"
APP_SECRET = "WzaTohEUFO0SY68HSeb9xdBwvEFuYqAM"
WEBHOOK_URL = "https://www.feishu.cn/flow/api/trigger-webhook/6e37ce15f9fc02ba1187a934b370be5d"

def get_ssh_config():
    ssh_config_path = os.path.expanduser('~/.ssh/config')
    config = SSHConfig()
    if os.path.exists(ssh_config_path):
        with open(ssh_config_path) as f:
            config.parse(f)
    return config

def get_hosts():
    config = get_ssh_config()
    hosts = []
    for host in config.get_hostnames():
        if host != '*' and host != 'eip':  # 跳过通配符主机
            host_config = config.lookup(host)
            hostname = host_config.get('hostname', host)
            hosts.append((host, hostname))
    return hosts

def create_ssh_client(host, timeout=10):
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    config = get_ssh_config()
    host_config = config.lookup(host)
    
    hostname = host_config.get('hostname', host)
    port = int(host_config.get('port', 22))
    username = host_config.get('user')
    key_filename = host_config.get('identityfile')
    
    if key_filename:
        key_filename = os.path.expanduser(key_filename[0])
    else:
        key_filename = os.path.expanduser('~/.ssh/id_rsa')
    
    try:
        logger.info(f"尝试连接到 {host} ({hostname})")
        client.connect(
            hostname,
            port=port,
            username=username,
            key_filename=key_filename,
            timeout=timeout  # 添加超时参数
        )
        logger.info(f"成功连接到 {host} ({hostname})")
        return client
    except paramiko.AuthenticationException:
        logger.error(f"认证失败: {host} ({hostname})")
    except paramiko.SSHException as ssh_exception:
        logger.error(f"SSH异常: {host} ({hostname}): {str(ssh_exception)}")
    except socket.timeout:
        logger.error(f"连接超时: {host} ({hostname})")
    except Exception as e:
        logger.error(f"无法连接到 {host} ({hostname}): {str(e)}")
    
    return None

def get_gpu_info(host):
    try:
        client = create_ssh_client(host)
        if not client:
            return '查询失败'
        
        stdin, stdout, stderr = client.exec_command('nvidia-smi --query-gpu=index,memory.used,memory.total,utilization.gpu,temperature.gpu --format=csv,nounits,noheader')
        output = stdout.read().decode().strip()
        
        gpu_info = []
        for line in output.split("\n"):
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
        
        client.close()
        return gpu_info
    except Exception as e:
        logger.error(f"{host} 无法连接或没有 nvidia-smi: {str(e)}")
        return '查询失败'

# 添加缓存装饰器
def timed_lru_cache(seconds: int, maxsize: int = 128):
    def wrapper_cache(func):
        func = lru_cache(maxsize=maxsize)(func)
        func.lifetime = seconds
        func.expiration = time.time() + func.lifetime

        @wraps(func)
        def wrapped_func(*args, **kwargs):
            if time.time() >= func.expiration:
                func.cache_clear()
                func.expiration = time.time() + func.lifetime
            return func(*args, **kwargs)

        return wrapped_func

    return wrapper_cache

@timed_lru_cache(seconds=30)
def check_all_gpus():
    hosts = get_hosts()
    hosts.sort(key=lambda x: int(x[0][1:]))
    all_gpu_info = {}
    for host,_ in hosts:
        gpu_info = get_gpu_info(host)
        if gpu_info:
            all_gpu_info[host] = gpu_info
    return all_gpu_info

@timed_lru_cache(seconds=30)
def check_cv_gpus():
    hosts = get_hosts()
    hosts = [(host,ip) for host,ip in hosts if host in ['u6', 'u7', 'u8', 'u9', 'u10', 'u11', 'u17', 'u18', 'u19', 'u20', 'u21', 'u4090', 'u4091','u22','u23']]
    hosts.sort(key=lambda x: int(x[0][1:]))
    all_gpu_info = {}
    for host,_ in hosts:
        gpu_info = get_gpu_info(host)
        if gpu_info:
            all_gpu_info[host] = gpu_info
    return all_gpu_info

@timed_lru_cache(seconds=30)
def check_llm_gpus():
    hosts = get_hosts()

    hosts = [(host,ip) for host,ip in hosts if host in ['u12', 'u13', 'u14', 'u15', 'u16']]
    hosts.sort(key=lambda x: int(x[0][1:]))
    all_gpu_info = {}
    for host,_ in hosts:
        gpu_info = get_gpu_info(host)
        if gpu_info:
            all_gpu_info[host] = gpu_info
    return all_gpu_info

@timed_lru_cache(seconds=30)
def check_u_gpus(host_num):
    hosts = get_hosts()
    hosts = [(host,ip) for host,ip in hosts if host in [f'u{host_num}']]
    all_gpu_info = {}
    for host,_ in hosts:
        gpu_info = get_gpu_info(host)
        if gpu_info:
            all_gpu_info[host] = gpu_info
    return all_gpu_info

def format_gpu_message(all_gpu_info, threshold=5):
    message = "GPU Report:\n\n"
    for host, gpus in all_gpu_info.items():
        message += f"Host: {host}\n"
        for gpu in gpus:
            if isinstance(gpu,str) or gpu["mem_usage_percent"] > threshold:
                continue
            message += f"  GPU {gpu['index']}: Memory {gpu['mem_usage_percent']:.2f}% ({gpu['mem_used']:.0f}/{gpu['mem_total']:.0f} MB), "
            message += f"Utilization {gpu['gpu_util']:.2f}%, Temperature {gpu['temperature']:.1f}°C\n"
        message += "\n"
    return message

def get_nfs_info(host):
    client = None
    try:
        client = create_ssh_client(host)
        if not client:
            return '查询失败'
        
        stdin, stdout, stderr = client.exec_command('/mnt/shuiyunhao/conda/envs/ipa/bin/python /mnt/shuiyunhao/nfs_troubleshoot.py')
        exit_status = stdout.channel.recv_exit_status()
        if exit_status != 0:
            logger.error(f"{host} NFS统计信息获取失败: 退出状态 {exit_status}")
            return '查询失败'

        output = stdout.read().decode().strip()
        
        # 解析输出，只获取10.60.222.218:/的信息
        target_info = None
        current_mount = None
        
        for line in output.split('\n'):
            if '/' in line:  # 新的挂载点开始
                current_mount = line.strip()
            elif current_mount and '10.60.222.218:/' in current_mount:
                parts = line.strip().split()
                if len(parts) >= 9:  # 确保有足够的数据
                    target_info = {
                        'mount': current_mount,
                        'timestamp': parts[0],
                        'stats': {
                            'GETATTR': int(parts[1]),
                            'LOOKUP': int(parts[2]),
                            'ACCESS': int(parts[3]),
                            'READDIR': int(parts[4]),
                            'OPEN': int(parts[5]),
                            'CLOSE': int(parts[6]),
                            'READ': int(parts[7]),
                            'WRITE': int(parts[8])
                        }
                    }
        
        return target_info
    except Exception as e:
        logger.error(f"{host} NFS统计信息获取失败: {str(e)}")
        return '查询失败'
    finally:
        if client:
            try:
                client.close()
                logger.debug(f"成功关闭到 {host} 的SSH连接")
            except:
                pass

@timed_lru_cache(seconds=30)
def check_all_nfs():
    hosts = get_hosts()
    hosts.sort(key=lambda x: int(x[0][1:]))
    all_nfs_info = {}
    max_io_host = None
    max_io = 0
    
    for host, _ in hosts:
        nfs_info = get_nfs_info(host)
        if isinstance(nfs_info, dict):
            all_nfs_info[host] = nfs_info
            total_io = nfs_info['operations']['total_io']
            if total_io > max_io:
                max_io = total_io
                max_io_host = host
    
    return all_nfs_info, max_io_host

def process_host(host_tuple):
    """辅助函数用于进程池处理"""
    host, _ = host_tuple
    return host, get_nfs_info(host)

def check_cv_nfs():
    hosts = get_hosts()
    hosts = [(host,ip) for host,ip in hosts if host in ['u6', 'u7', 'u8', 'u9', 'u10', 'u11', 'u17', 'u18', 'u19']]
    hosts.sort(key=lambda x: int(x[0][1:]))
    
    # 创建进程池，使用8个进程
    with Pool(processes=8) as pool:
        # 使用进程池map函数并行处理，改用独立的函数而不是lambda
        results = pool.map(process_host, hosts)
    
    # 整理结果
    all_nfs_info = {host: info for host, info in results if isinstance(info, dict)}
    return all_nfs_info

def check_llm_nfs():
    hosts = get_hosts()
    hosts = [(host,ip) for host,ip in hosts if host in ['u12', 'u13', 'u14', 'u15', 'u16', 'u1', 'u2', 'u3', 'u4', 'u5']]
    hosts.sort(key=lambda x: int(x[0][1:]))
    
    # 创建进程池，使用8个进程
    with Pool(processes=8) as pool:
        # 使用进程池map函数并行处理
        results = pool.map(process_host, hosts)
    
    # 整理结果
    all_nfs_info = {host: info for host, info in results if isinstance(info, dict)}
    return all_nfs_info

def format_nfs_message(all_nfs_info):
    message = "NFS 操作统计报告 (10.60.222.218:/):\n\n"
    
    # 收集所有有效的统计信息
    valid_stats = {}
    for host, info in all_nfs_info.items():
        if isinstance(info, dict) and info.get('stats'):
            valid_stats[host] = info['stats']
    
    # 对每种操作类型进行排序和显示
    operations = ['GETATTR', 'LOOKUP', 'ACCESS', 'READDIR', 'OPEN', 'CLOSE', 'READ', 'WRITE']
    
    for op in operations:
        message += f"\n{op} 操作排名:\n"
        sorted_hosts = sorted(valid_stats.items(), key=lambda x: x[1][op], reverse=True)
        for host, stats in sorted_hosts[:3]:  # 只显示前三名
            message += f"{host}: {stats[op]}\n"
    
    return message

@app.route('/', methods=['POST'])
def handle_message():
    try:
        raw_data = request.get_data(as_text=True)
        logger.info(f"收到原始数据: {raw_data}")

        if "cv" == raw_data.lower():
            all_gpu_info = check_cv_gpus()
            gpu_status = format_gpu_message(all_gpu_info)
            logger.info("成功发送飞书消息")
            headers = {
                'Content-Type': 'application/json; charset=utf-8'
            }
            return make_response(jsonify({"type": "cv", "message": gpu_status}), 200, headers)

        if "llm" == raw_data.lower():
            all_gpu_info = check_llm_gpus()
            gpu_status = format_gpu_message(all_gpu_info)
            logger.info("成功发送飞书消息")
            headers = {
                'Content-Type': 'application/json; charset=utf-8'
            }
            return make_response(jsonify({"type": "llm", "message": gpu_status}), 200, headers)

        if "all" == raw_data.lower():
            all_gpu_info = check_all_gpus()
            gpu_status = format_gpu_message(all_gpu_info)
            logger.info("成功发送飞书消息")
            headers = {
                'Content-Type': 'application/json; charset=utf-8'
            }
            return make_response(jsonify({"type": "all", "message": gpu_status}), 200, headers)

        if "u" in raw_data.lower():
            host_num = ''.join(raw_data.split("u")[1:])
            all_gpu_info = check_u_gpus(host_num)
            gpu_status = format_gpu_message(all_gpu_info, threshold=100)
            logger.info("成功发送飞书消息")
            headers = {
                'Content-Type': 'application/json; charset=utf-8'
            }
            return make_response(jsonify({"type": raw_data, "message": gpu_status}), 200, headers)

        if "nfs_all" in raw_data.lower():
            all_nfs_info = check_all_nfs()
            nfs_status = format_nfs_message(all_nfs_info)
            logger.info("成功获取NFS信息")
            headers = {
                'Content-Type': 'application/json; charset=utf-8'
            }
            return make_response(jsonify({"type": "nfs_all", "message": nfs_status}), 200, headers)

        if "nfs_cv" in raw_data.lower():
            all_nfs_info = check_cv_nfs()
            nfs_status = format_nfs_message(all_nfs_info)
            logger.info("成功获取NFS信息")
            headers = {
                'Content-Type': 'application/json; charset=utf-8'
            }
            return make_response(jsonify({"type": "nfs_cv", "message": nfs_status}), 200, headers)

        if "nfs_llm" in raw_data.lower():
            all_nfs_info = check_llm_nfs()
            nfs_status = format_nfs_message(all_nfs_info)
            logger.info("成功获取NFS信息")
            headers = {
                'Content-Type': 'application/json; charset=utf-8'
            }
            return make_response(jsonify({"type": "nfs_llm", "message": nfs_status}), 200, headers)

    except Exception as e:
        logger.exception(f"处理消息时发生错误: {str(e)}")
        headers = {
            'Content-Type': 'application/json; charset=utf-8'
        }
        return make_response(jsonify({"type": 'error', "message": "处理请求时发生错误"}), 500, headers)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=False)