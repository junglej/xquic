import json
import argparse
import sys
import os
from collections import defaultdict
import matplotlib.pyplot as plt

# --- 新增: 使用 Matplotlib 的绘图函数 ---
def plot_with_matplotlib(data_by_path, title, y_label, unit, file_prefix, start_time):
    """
    使用 Matplotlib 为多条路径绘制并保存时间序列图。
    data_by_path: 一个字典 {path_id: [(timestamp, value), ...]}
    file_prefix: 用于生成输出文件名的前缀 (例如 ODCID)
    start_time: 整个追踪的起始时间戳，用于计算相对时间
    """
    print(f"--- Generating plot: {title} ---")
    
    paths_with_data = {p: d for p, d in data_by_path.items() if d}
    if not paths_with_data:
        print("No data available to plot for this metric.")
        return

    fig, ax = plt.subplots(figsize=(12, 6))
    
    path_symbols = ['-o', '-s', '-^', '-x', '-+']
    path_colors = ['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728', '#9467bd']

    for i, (path_id, data) in enumerate(paths_with_data.items()):
        # 将绝对时间戳转换为相对于开始时间的秒数
        times_sec = [(t - start_time) / 1000.0 for t, v in data]
        values = [v for t, v in data]
        
        symbol = path_symbols[i % len(path_symbols)]
        color = path_colors[i % len(path_colors)]
        ax.plot(times_sec, values, symbol, label=f'Path {path_id}', markersize=4, color=color)

    ax.set_title(title, fontsize=16)
    ax.set_xlabel("Time (seconds)", fontsize=12)
    ax.set_ylabel(f"{y_label} ({unit})", fontsize=12)
    ax.grid(True, which='both', linestyle='--', linewidth=0.5)
    ax.legend()
    
    # 自动调整Y轴从0开始，以获得更好的视觉效果
    ax.set_ylim(bottom=0)

    # 生成安全的文件名并保存
    safe_title = title.replace(' ', '_').replace('(', '').replace(')', '')
    output_filename = f"{file_prefix}_{safe_title}.png"
    plt.savefig(output_filename, dpi=150)
    plt.close(fig) # 关闭图形以释放内存
    print(f"Plot saved to: {output_filename}")


# --- 核心分析逻辑 (大部分保持不变) ---
def calculate_goodput(acked_data_by_path, interval_ms=1000):
    goodput_by_path = defaultdict(list)
    if not acked_data_by_path:
        return goodput_by_path
        
    start_time = min(data[0][0] for data in acked_data_by_path.values() if data)

    for path_id, data in acked_data_by_path.items():
        if not data:
            continue
            
        bins = defaultdict(int)
        for timestamp, bytes_acked in data:
            bin_index = int((timestamp - start_time) / interval_ms)
            bins[bin_index] += bytes_acked
            
        if not bins:
            continue

        interval_s = interval_ms / 1000.0
        sorted_bins = sorted(bins.items())
        
        for bin_index, total_bytes in sorted_bins:
            timestamp = start_time + (bin_index * interval_ms)
            mbps = (total_bytes * 8) / interval_s / 1_000_000
            goodput_by_path[path_id].append((timestamp, mbps))
            
    return goodput_by_path

def analyze_single_trace(trace, file_prefix):
    if "common_fields" not in trace or "ODCID" not in trace["common_fields"]:
        print("Skipping trace: Missing ODCID.")
        return

    odcid = trace["common_fields"]["ODCID"]
    vantage_point = trace.get("vantage_point", {}).get("type", "unknown")
    print(f"Connection ODCID: {odcid} ({vantage_point} view)")

    if "events" not in trace or not trace["events"]:
        print("No events found in this trace.")
        return

    start_time = trace["events"][0]["time"]

    stats = defaultdict(lambda: defaultdict(int))
    rtt_samples = defaultdict(list)
    acked_data = defaultdict(list)
    path_ids = {0}
    
    packet_size_map = defaultdict(dict)
    for event in trace["events"]:
        if event.get("name") == "quic:packet_sent":
            path_id = event.get("path", 0)
            data = event.get("data", {})
            if "header" in data and "raw" in data:
                pkt_num = data["header"].get("packet_number")
                pkt_size = data["raw"].get("length")
                if isinstance(pkt_num, int) and pkt_size is not None:
                     packet_size_map[path_id][pkt_num] = pkt_size

    for event in trace["events"]:
        event_name = event.get("name", "")
        path_id = event.get("path", 0)
        path_ids.add(path_id)
        data = event.get("data", {})

        if event_name == "quic:packet_sent":
            stats[path_id]['packets_sent'] += 1
            if "raw" in data:
                stats[path_id]['bytes_sent'] += data.get("raw", {}).get("length", 0)

        elif event_name == "quic:packet_received":
            stats[path_id]['packets_received'] += 1
            if "raw" in data:
                stats[path_id]['bytes_received'] += data.get("raw", {}).get("length", 0)
        
        elif event_name == "recovery:packet_lost":
            stats[path_id]['packets_lost'] += 1

        elif event_name == "recovery:metrics_updated":
            if "latest_rtt" in data:
                rtt_samples[path_id].append((event["time"], data["latest_rtt"] / 1000.0))
        
        elif event_name == "quic:packets_acked":
            acked_packets = data.get("packet_numbers", [])
            bytes_in_ack = 0
            for pkt_num in acked_packets:
                bytes_in_ack += packet_size_map[path_id].get(pkt_num, 0)
            if bytes_in_ack > 0:
                acked_data[path_id].append((event["time"], bytes_in_ack))

    if len(path_ids) <= 1 and not any(stats[p]['packets_sent'] > 0 for p in path_ids if p != 0):
         print("This is a single-path connection. Analyzing Path 0.")
    else:
        print(f"\n**Multi-Path connection detected. Analyzing {len(path_ids)} paths.**")
    
    goodput_by_path = calculate_goodput(acked_data, interval_ms=1000)
    
    # 使用matplotlib绘图
    file_prefix_with_vp = f"{file_prefix}_{odcid[:8]}_{vantage_point}"
    plot_with_matplotlib(rtt_samples, "RTT Over Time", "RTT", "ms", file_prefix_with_vp, start_time)
    plot_with_matplotlib(goodput_by_path, "Throughput (Goodput) Over Time", "Rate", "Mbps", file_prefix_with_vp, start_time)

    print("\n--- Quantitative Summary ---")
    for path_id in sorted(list(path_ids)):
        if rtt_samples[path_id]:
            avg_rtt = sum(val for _, val in rtt_samples[path_id]) / len(rtt_samples[path_id])
            stats[path_id]['avg_rtt_ms'] = avg_rtt
        else:
            stats[path_id]['avg_rtt_ms'] = float('nan') 

        if stats[path_id]['packets_sent'] > 0:
            loss_rate = (stats[path_id]['packets_lost'] / stats[path_id]['packets_sent']) * 100
            stats[path_id]['loss_rate_percent'] = loss_rate
        else:
            stats[path_id]['loss_rate_percent'] = 0.0
            
    header = f"{'Path ID':<8} | {'Total Bytes Sent':>18} | {'Total Packets Sent':>20} | {'Packets Lost':>15} | {'Loss Rate (%)':>15} | {'Avg RTT (ms)':>15}"
    print(header)
    print("-" * len(header))
    for path_id in sorted(list(path_ids)):
        if stats[path_id]['packets_sent'] == 0 and stats[path_id]['packets_received'] == 0:
            continue
        row = (
            f"{path_id:<8} | "
            f"{stats[path_id]['bytes_sent']:>18,} | "
            f"{stats[path_id]['packets_sent']:>20,} | "
            f"{stats[path_id]['packets_lost']:>15,} | "
            f"{stats[path_id]['loss_rate_percent']:>15.3f} | "
            f"{stats[path_id]['avg_rtt_ms']:>15.2f}"
        )
        print(row)

def main():
    parser = argparse.ArgumentParser(description="Visualize QUIC performance from an xquic-generated qlog file.")
    parser.add_argument("qlog_file", help="Path to the qlog JSON file.")
    args = parser.parse_args()

    if not os.path.exists(args.qlog_file):
        print(f"Error: File not found at '{args.qlog_file}'", file=sys.stderr)
        sys.exit(1)

    try:
        with open(args.qlog_file, 'r', encoding='utf-8', errors='ignore') as f:
            qlog_content = json.load(f)
    except json.JSONDecodeError as e:
        print(f"Error: Failed to parse '{args.qlog_file}'. Not a valid JSON file. Details: {e}", file=sys.stderr)
        sys.exit(1)

    if "traces" not in qlog_content:
        print("Error: 'traces' key not found in the qlog file.", file=sys.stderr)
        return

    # 获取qlog文件的前缀，用于命名输出的图片
    file_prefix = os.path.splitext(os.path.basename(args.qlog_file))[0]

    for i, trace in enumerate(qlog_content["traces"]):
        print(f"==================== Analyzing Trace #{i+1} ====================")
        analyze_single_trace(trace, file_prefix)
        print("=" * 60 + "\n")

if __name__ == "__main__":
    main()