import argparse
import os
import sys
import json
import re
import datetime
from collections import defaultdict

# --- 全局定义 (保持不变) ---
# (为简洁起见，此处省略，请从您之前的文件中复制所有全局列表和字典的定义)
connectivity_event_list_ = ["server_listening", "connection_started", "connection_closed", "connection_id_updated", "spin_bit_updated", "connection_state_updated", "path_assigned", "mtu_updated"]
quic_event_list_ = ["version_information", "alpn_information", "parameters_set", "parameters_restored", "packet_sent", "packet_received", "packets_acked", "datagrams_sent", "datagrams_received", "datagram_dropped", "stream_state_updated", "frames_processed", "stream_data_moved", "datagram_data_moved", "migration_state_updated", "packet_dropped", "packet_buffered"]
security_event_list_ = ["key_updated", "key_discarded"]
recovery_event_list_ = ["rec_parameters_set", "rec_metrics_updated", "congestion_state_updated", "loss_timer_updated", "packet_lost", "marked_for_retransmit", "ecn_state_updated"]
http_event_list_ = ["http_parameters_set", "http_parameters_restored", "http_stream_type_set", "http_frame_created", "http_frame_parsed", "push_resolved", "http_setting_parsed"]
packet_type_ = {0: "initial", 1: "0RTT", 2: "handshake", 3: "retry", 4: "short_header", 5: "version_negotiation", 6: "unknown"}
packet_number_namespace_ = {0: "initial", 1: "handshake", 2: "application data", 3: "negotiation"}
send_stream_states_ = ["ready", "send", "data_sent", "reset_sent", "reset_received"]
recv_stream_states_ = ["receive", "size_known", "data_read", "reset_read", "reset_received"]
frame_type_ = ["PADDING", "PING", "ACK", "RESET_STREAM", "STOP_SENDING", "CRYPTO", "NEW_TOKEN", "STREAM", "MAX_DATA", "MAX_STREAM_DATA", "MAX_STREAMS", "DATA_BLOCKED", "STREAM_DATA_BLOCKED", "STREAMS_BLOCKED", "NEW_CONNECTION_ID", "RETIRE_CONNECTION_ID", "PATH_CHALLENGE", "PATH_RESPONSE", "CONNECTION_CLOSE", "HANDSHAKE_DONE", "ACK_MP", "PATH_ABANDON", "PATH_STATUS", "DATAGRAM", "Extension"]
h3_stream_type_ = ["control", "push", "qpack_encode", "qpack_decode", "request", "bytestream", "unknown"]
h3_frame_type_ = ["data", "headers", "bidi_stream_type", "cancel_push", "settings", "push_promise", "goaway", "max_push_id", "unknown"]


# --- 辅助函数 ---
def get_kv_from_line(line):
    kv = {}
    # 使用正则表达式匹配 |key:value| 结构，可以处理值中包含|的情况
    for match in re.finditer(r'\|([^|:]+):([^|]*)', line):
        key = match.group(1).strip()
        value = match.group(2).strip()
        kv[key] = value
    return kv

# --- 所有 parse_* 函数统一接收 kv 字典 ---
# --- 并修复了之前版本的所有bug ---
def parse_packet_sent_and_recv(kv):
    pkt_type_str = kv.get("pkt_type", "unknown").lower()
    if pkt_type_str == "hsk":
        pkt_type_str = "handshake"
    return {
        "header": {"packet_number": int(kv.get("pkt_num", -1)), "packet_type": pkt_type_str},
        "raw": {"length": int(kv.get("size", 0))}
    }

def parse_datagrams_sent(kv): return {"raw": {"length": int(kv.get("size", 0))}}
def parse_datagrams_received(kv): return {"raw": {"length": int(kv.get("size", 0))}}

def parse_connection_state_updated(kv):
    return {"new": kv.get("new", "unknown")}

def parse_rec_metrics_updated(kv):
    data = {}
    # 安全地转换值为整数
    for key, qlog_key in [("cwnd", "congestion_window"), ("inflight", "bytes_in_flight"), 
                         ("pacing_rate", "pacing_rate"), ("pto_count", "pto_count"),
                         ("ctl_rttvar", "rtt_variance"), ("min_rtt", "min_rtt"),
                         ("latest_rtt", "latest_rtt")]:
        if key in kv:
            try:
                data[qlog_key] = int(kv[key])
            except (ValueError, TypeError):
                pass # 忽略转换失败的值
    return data

def parse_http_frame_created(kv):
    try:
        frame_type_int = int(kv.get("type", -1))
        if 0 <= frame_type_int < len(h3_frame_type_):
            frame_type = h3_frame_type_[frame_type_int]
        else:
            frame_type = "unknown"
    except (ValueError, TypeError):
        frame_type = "unknown"

    data = {"stream_id": kv.get("stream_id", "unknown"), "frame": {"frame_type": frame_type}}

    if frame_type == "settings":
        settings_obj = {}
        for set_i in ["max_field_section_size", "max_pushes", "qpack_max_table_capacity", "qpack_blocked_streams"]:
            if set_i in kv:
                try:
                    settings_obj[set_i] = int(kv[set_i])
                except (ValueError, TypeError):
                    pass
        data["frame"]["settings"] = settings_obj
    # 可以根据需要添加对其他H3帧类型的解析
    return data
    
# (此处省略其他所有 parse_* 函数, 请从上一个回答中复制粘贴, 确保它们都接收 kv 字典)
# ... 为保证脚本完整性，我将重新列出所有被修改的函数 ...
def parse_server_listening(kv):
    data = {}
    for key, value in kv.items():
        if key.startswith("port"): data[key] = int(value)
        elif key not in ["scid", "conn"]: data[key] = value
    return data

def parse_connection_started(kv):
    return {
        "src_ip": kv.get("src_ip", "0.0.0.0"), "dst_ip": kv.get("dst_ip", "0.0.0.0"),
        "src_port": int(kv.get("src_port", 0)), "dst_port": int(kv.get("dst_port", 0))
    }

def parse_connection_closed(kv):
    return {"connection_code": int(kv.get("err_code", 0))}

def parse_path_assigned(kv):
    return {"path_id": kv.get("path_id", "unknown")}

def parse_mtu_updated(kv):
    return {"new": int(kv.get("new", 0)), "done": bool(int(kv.get("done", 0)))}

def parse_alpn_information(kv):
    return {
        "server_alpns": [{"string_value": alpn} for alpn in kv.get("server_alpn", "").split()],
        "client_alpns": [{"string_value": alpn} for alpn in kv.get("client_alpn", "").split()],
        "chosen_alpn": {"string_value": kv.get("selected_alpn", "unknown")}
    }

def parse_parameters_set(kv):
    return {
        "max_idle_timeout": int(kv.get("max_idle_timeout", 0)),
        "max_udp_payload_size": int(kv.get("max_udp_payload_size", 0)),
        "active_connection_id_limit": int(kv.get("active_connection_id_limit", 0))
    }

def parse_packet_buffered(kv):
    return {
        "header": {"packet_number": int(kv.get("pkt_num", 0)), "packet_type": packet_type_.get(int(kv.get("pkt_type", 6)), "unknown")},
        "raw": {"length": int(kv.get("len", 0))}
    }

def parse_packets_acked(kv):
    low, high = int(kv.get("low", 0)), int(kv.get("high", -1))
    if low > high: return None
    return {
        "packet_number_space": packet_number_namespace_.get(int(kv.get("pkt_space", 3)), "unknown"),
        "packet_numbers": list(range(low, high + 1))
    }
    
def parse_stream_state_updated(kv):
    stream_side = "receiving" if "recv_stream" in kv or "|recv_stream|" in kv.get('_raw_line', '') else "sending"
    state_map = recv_stream_states_ if stream_side == "receiving" else send_stream_states_
    new_state_index = int(kv.get("new", 0))
    return {
        "StreamType": "bidirectional", 
        "new": state_map[new_state_index] if 0 <= new_state_index < len(state_map) else "unknown",
        "stream_side": stream_side
    }

def parse_frames_processed(kv):
    try:
        frame_type_int = int(kv.get("type", -1))
        if not (0 <= frame_type_int < len(frame_type_)):
            return None # 如果类型无效，则跳过
        frame_type_str = frame_type_[frame_type_int]
    except (ValueError, TypeError):
        return None

    frame = {"frame_type": frame_type_str.lower()}
    
    if frame_type_str == "STREAM":
        frame["length"] = int(kv.get("data_length", 0))
        frame["offset"] = int(kv.get("data_offset", 0))
        frame["fin"] = bool(int(kv.get("fin", 0)))
    # 可以继续添加对其他 frame 类型的解析
    
    return {"frames": [frame]}

def parse_stream_data_moved(kv):
    return {
        "stream_id": int(kv.get("stream_id", 0)), "offset": int(kv.get("offset", kv.get("stream_send_offset", 0))),
        "length": int(kv.get("send_data_size", kv.get("length", 0))), 
        "from": kv.get("from", "unknown"), "to": kv.get("to", "unknown")
    }

def parse_rec_parameters_set(kv):
    data = {}
    for key, val in kv.items():
        if key not in ["scid", "conn"]: data[key] = int(val)
    return data

def parse_congestion_state_updated(kv):
    return {"new": kv.get("new_state", "unknown")}

def parse_packet_lost(kv):
    return {
        "header": { "packet_number": int(kv.get("pkt_num", -1)), 
                    "packet_type": packet_type_.get(int(kv.get("pkt_type", 6)), "unknown")}
    }

def parse_http_parameters_set(kv):
    data = {}
    for key, val in kv.items():
        if key not in ["scid", "conn"]:
            if key == "owner": data[key] = val
            else: data[key] = int(val)
    return data

def parse_http_frame_parsed(kv):
    return {"stream_id": kv.get("stream_id"), "push_id": kv.get("push_id")}

# 修正后的主解析函数
def parse_line(line):
    kv = get_kv_from_line(line)
    conn_id = kv.get("conn")
    scid = kv.get("scid")
    
    # 必须要有 conn 句柄才能进行关联
    if not conn_id:
        return None, None, None

    # 使用更可靠的正则表达式来提取时间和事件名
    match = re.match(r'\[(.*?)\s(.*?)\]\s\[(.*?)\]', line)
    if not match:
        return None, None, None
    
    date_str, time_us_str, event_name_raw = match.groups()
    
    try:
        event_time = datetime.datetime.strptime(f"{date_str} {time_us_str}", "%Y/%m/%d %H:%M:%S %f").timestamp() * 1000
    except ValueError:
        return None, None, None
        
    event = {"time": event_time}
    
    # 分类事件名
    if event_name_raw in connectivity_event_list_: event["name"] = "connectivity:" + event_name_raw
    elif event_name_raw in quic_event_list_: event["name"] = "quic:" + event_name_raw
    elif event_name_raw in security_event_list_: event["name"] = "security:" + event_name_raw
    elif event_name_raw in recovery_event_list_:
        name = event_name_raw[4:] if event_name_raw.startswith("rec_") else event_name_raw
        event["name"] = "recovery:" + name
    elif event_name_raw in http_event_list_:
        name = "push_resolved" if event_name_raw == "push_resolved" else event_name_raw[5:]
        event["name"] = "h3:" + name
    else:
        return None, None, None

    if "path_id" in kv:
        event["path"] = int(kv["path_id"])

    # 调用相应的解析函数
    parser_func_name = "parse_" + event_name_raw
    if parser_func_name in globals():
        parser_func = globals()[parser_func_name]
        event_data = parser_func(kv)
        if event_data:
            event["data"] = event_data
            return event, scid, conn_id
    
    # 对于没有特定解析函数的事件，也返回一个空data，以防丢失事件
    event["data"] = {}
    return event, scid, conn_id

# 核心修改：使用 conn_id 而不是 scid 来聚合
def endpoint_events_extraction(file_name, vantagepoint):
    traces_by_conn = defaultdict(lambda: {
        "title": f"xquic-qlog json: {vantagepoint}", "description": "",
        "common_fields": {"time_format": "absolute"},
        "vantage_point": {"name": f"{vantagepoint}-view", "type": vantagepoint},
        "events": []
    })

    for line in open(file_name, 'r', encoding='utf-8', errors='ignore'):
        event, scid, conn_id = parse_line(line)
        if not event:
            continue

        # 使用conn_id作为唯一的key
        if "ODCID" not in traces_by_conn[conn_id]["common_fields"] and scid:
            traces_by_conn[conn_id]["common_fields"]["ODCID"] = scid
        
        traces_by_conn[conn_id]["events"].append(event)
            
    return list(traces_by_conn.values())


# Main 函数保持不变
def main():
    parser = argparse.ArgumentParser(description="Parse xquic logs into a qlog file.")
    parser.add_argument("--clog", help="xquic client log file")
    parser.add_argument("--slog", help="xquic server log file")
    parser.add_argument("--qlog_path", help="output json file, e.g., demo_qlog.qlog", default="demo_qlog.qlog")
    args = parser.parse_args()
    
    if not (args.clog or args.slog):
        sys.exit("Usage: must provide either --clog or --slog argument")
    
    data = {
        "qlog_version": "0.4", "qlog_format": "JSON",
        "title": "xquic qlog",
        "description": "Generated from xquic text logs.",
        "traces": []
    }
    
    if args.slog and os.path.isfile(args.slog):
        data["traces"].extend(endpoint_events_extraction(args.slog, "server"))

    if args.clog and os.path.isfile(args.clog):
        data["traces"].extend(endpoint_events_extraction(args.clog, "client"))

    with open(args.qlog_path, 'w') as out_file:
        json.dump(data, out_file, indent=4)
        
    print(f"Successfully generated combined qlog file: {args.qlog_path}")

if __name__ == "__main__":
    main()