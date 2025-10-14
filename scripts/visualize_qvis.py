import json
import argparse
import sys
import os
from collections import defaultdict
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker

# --- Matplotlib 绘图函数 (升级版) ---
def plot_dual_perspective_graph(data_groups, title, y_label, unit, file_prefix, start_time):
    """
    使用 Matplotlib 在同一个图表中为客户端和服务端绘制多路径时间序列图。
    data_groups: {
        "client": {path_id: [(timestamp, value), ...]},
        "server": {path_id: [(timestamp, value), ...]}
    }
    """
    print(f"--- Generating plot: {title} ---")
    
    # 检查是否有任何数据可以绘制
    if not any(data for group in data_groups.values() for data in group.values()):
        print("No data available to plot for this metric.")
        return

    fig, ax = plt.subplots(figsize=(15, 7))
    
    # 为不同视角和路径定义样式
    styles = {
        'client': {'color': '#1f77b4', 'linestyle': '-', 'marker': 'o'},
        'server': {'color': '#ff7f0e', 'linestyle': '--', 'marker': 'x'}
    }
    path_markers = ['o', 's', '^', 'x', '+'] # 每个路径用不同标记

    for vantage_point, data_by_path in data_groups.items():
        if not data_by_path:
            continue
        
        for i, (path_id, data) in enumerate(data_by_path.items()):
            if not data:
                continue
            
            times_sec = [(t - start_time) / 1000.0 for t, v in data]
            values = [v for t, v in data]
            
            label = f"{vantage_point.capitalize()} Path {path_id}"
            ax.plot(times_sec, values, 
                    label=label, 
                    color=styles[vantage_point]['color'],
                    linestyle=styles[vantage_point]['linestyle'],
                    marker=path_markers[i % len(path_markers)], 
                    markersize=4, alpha=0.8)

    ax.set_title(title, fontsize=16)
    ax.set_xlabel("Time (seconds)", fontsize=12)
    ax.set_ylabel(f"{y_label} ({unit})", fontsize=12)
    ax.grid(True, which='both', linestyle='--', linewidth=0.5)
    ax.legend()
    ax.set_ylim(bottom=0)
    # 格式化Y轴，使用逗号分隔千位
    ax.get_yaxis().set_major_formatter(mticker.FuncFormatter(lambda x, p: format(int(x), ',')))


    safe_title = title.replace(' ', '_').replace('(', '').replace(')', '')
    output_filename = f"{file_prefix}_{safe_title}.png"
    plt.savefig(output_filename, dpi=150, bbox_inches='tight')
    plt.close(fig)
    print(f"Plot saved to: {output_filename}")

# --- 核心分析逻辑 (升级版) ---
def calculate_goodput(acked_data_by_path, interval_ms=1000, global_start_time=0):
    goodput_by_path = defaultdict(list)
    if not acked_data_by_path:
        return goodput_by_path
        
    start_time = global_start_time

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

def analyze_trace_group(trace_group, file_prefix):
    """
    分析一个关联的trace组 (例如，一个客户端和一个服务端的trace)。
    """
    client_trace = None
    server_trace = None
    for trace in trace_group:
        if trace.get("vantage_point", {}).get("type") == "client":
            client_trace = trace
        elif trace.get("vantage_point", {}).get("type") == "server":
            server_trace = trace

    if not (client_trace and server_trace):
        print("Warning: Could not find both client and server traces for this group. Analyzing individually.")
        for trace in trace_group:
             analyze_single_trace(trace, file_prefix)
        return

    # --- 数据提取 ---
    all_events = client_trace.get("events", []) + server_trace.get("events", [])
    if not all_events:
        print("No events found in this trace group.")
        return
        
    all_events.sort(key=lambda e: e["time"])
    global_start_time = all_events[0]["time"]
    odcid = client_trace["common_fields"]["ODCID"]
    
    print(f"Analyzing matched connection: Client ODCID {odcid}")

    rtt_groups = {'client': defaultdict(list), 'server': defaultdict(list)}
    acked_data_groups = {'client': defaultdict(list), 'server': defaultdict(list)}
    
    # 预处理：构建packet_size_map
    packet_size_maps = {'client': defaultdict(dict), 'server': defaultdict(dict)}
    for trace in [client_trace, server_trace]:
        vp = trace["vantage_point"]["type"]
        for event in trace.get("events", []):
            if event.get("name") == "quic:packet_sent":
                path_id = event.get("path", 0)
                data = event.get("data", {})
                if "header" in data and "raw" in data:
                    pkt_num = data["header"].get("packet_number")
                    pkt_size = data["raw"].get("length")
                    if isinstance(pkt_num, int) and pkt_size is not None:
                        packet_size_maps[vp][path_id][pkt_num] = pkt_size

    # 主处理循环
    for trace in [client_trace, server_trace]:
        vp = trace["vantage_point"]["type"]
        for event in trace.get("events", []):
            event_name = event.get("name", "")
            path_id = event.get("path", 0)
            data = event.get("data", {})

            if event_name == "recovery:metrics_updated":
                if "latest_rtt" in data:
                    rtt_groups[vp][path_id].append((event["time"], data["latest_rtt"] / 1000.0))
            
            elif event_name == "quic:packets_acked":
                acked_packets = data.get("packet_numbers", [])
                bytes_in_ack = 0
                # 注意：这里假设ACK是针对对端发送的包，所以要用对端的packet_size_map
                # 但qlog没有直接关联，我们只能假设ACK的是本端记录的已发送包
                # 这是一个简化的假设，但在大多数情况下是合理的
                for pkt_num in acked_packets:
                     bytes_in_ack += packet_size_maps[vp][path_id].get(pkt_num, 0)
                if bytes_in_ack > 0:
                    acked_data_groups[vp][path_id].append((event["time"], bytes_in_ack))
    
    # --- 可视化 ---
    file_prefix_with_id = f"{file_prefix}_{odcid[:8]}"
    goodput_client = calculate_goodput(acked_data_groups['client'], global_start_time=global_start_time)
    goodput_server = calculate_goodput(acked_data_groups['server'], global_start_time=global_start_time)

    plot_dual_perspective_graph({'client': rtt_samples['client'], 'server': rtt_samples['server']}, 
                                f"RTT Over Time (ODCID: {odcid[:8]})", "RTT", "ms", file_prefix_with_id, global_start_time)
    
    # 客户端看到的是下载吞吐量，服务端看到的是发送吞吐量
    plot_dual_perspective_graph({'client': goodput_client, 'server': goodput_server}, 
                                f"Throughput (Goodput) Over Time (ODCID: {odcid[:8]})", "Rate", "Mbps", file_prefix_with_id, global_start_time)


def analyze_single_trace(trace, file_prefix):
    """Fallback for analyzing traces that couldn't be grouped."""
    # (此函数从上个脚本复制而来，用于处理未配对的trace)
    odcid = trace["common_fields"]["ODCID"]
    vantage_point = trace.get("vantage_point", {}).get("type", "unknown")
    print(f"Analyzing single trace: ODCID {odcid} ({vantage_point} view)")
    # (此处省略单trace的分析和绘图逻辑，以保持简洁，您可以从上一个脚本复制过来)
    # 为简单起见，这里只打印一条信息
    print("This trace was not paired with its counterpart. Individual analysis is not implemented in this version.")


# --- 主程序入口 (升级版) ---
def main():
    parser = argparse.ArgumentParser(description="Visualize QUIC performance from a qlog file, correlating client and server views.")
    parser.add_argument("qlog_file", help="Path to the combined qlog JSON file.")
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

    # --- 核心分组逻辑 ---
    grouped_by_odcid = defaultdict(list)
    for trace in qlog_content["traces"]:
        odcid = trace.get("common_fields", {}).get("ODCID")
        if odcid:
            grouped_by_odcid[odcid].append(trace)
    
    file_prefix = os.path.splitext(os.path.basename(args.qlog_file))[0]
    
    if not grouped_by_odcid:
        print("No valid traces with ODCID found.")
        return

    print(f"Found {len(grouped_by_odcid)} unique connection(s) in the qlog file.")

    for odcid, trace_group in grouped_by_odcid.items():
        print(f"\n==================== Analyzing Connection Group: {odcid} ====================")
        analyze_trace_group(trace_group, file_prefix)
        print("=" * 70 + "\n")


if __name__ == "__main__":
    main()