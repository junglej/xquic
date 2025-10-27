#!/usr/bin/env python3
import re
import json
import sys
from collections import defaultdict
import matplotlib.pyplot as plt

class MPLogAnalyzer:
    def __init__(self, log_file):
        self.log_file = log_file
        self.metrics = defaultdict(list)
        self.path_rtt_data = defaultdict(list)
        self.path_interface_map = {}  # ✅ 新增：path_id到网卡的映射
        self.events = []
        self.handover_times = []
        
    def parse_log(self):
        """Parse log file"""
        with open(self.log_file, 'r') as f:
            for line in f:
                # print(line.strip())
                # Extract METRICS_JSON
                if 'METRICS_JSON' in line:
                    self._parse_metrics(line)
                # Extract xquic internal path_srtt
                elif 'path_srtt:' in line and 'path_id:' in line:
                    self._parse_xquic_path_rtt(line)
                # ✅ Extract interface mapping
                elif 'PATH_CREATED' in line or 'interface:' in line:
                    self._parse_interface_mapping(line)
                # Extract key events
                elif any(x in line for x in ['PATH_CREATED', 'PATH_REMOVED', 
                                              'HANDSHAKE', 'REBINDING']):
                    self._parse_event(line)
    
    def _parse_interface_mapping(self, line):
        """✅ Extract path_id to interface mapping"""
        try:
            # Look for patterns like: interface:wlp3s0|path_id:0
            interface_match = re.search(r'interface:(\w+)', line)
            path_match = re.search(r'path_id:(\d+)', line)
            
            if interface_match and path_match:
                interface = interface_match.group(1)
                path_id = int(path_match.group(1))
                self.path_interface_map[path_id] = interface
                print(f"  📡 Detected mapping: Path {path_id} -> {interface}")
            
            # Alternative pattern: interface_index:0|interface:wlp3s0
            elif 'interface_index:' in line and 'interface:' in line:
                idx_match = re.search(r'interface_index:(\d+)', line)
                interface_match = re.search(r'interface:(\w+)', line)
                if idx_match and interface_match:
                    path_id = int(idx_match.group(1))
                    interface = interface_match.group(1)
                    self.path_interface_map[path_id] = interface
                    print(f"  📡 Detected mapping: Path {path_id} -> {interface}")
        except Exception as e:
            pass
    
    def _get_path_label(self, path_id):
        """✅ Get path label (interface name or fallback to path_id)"""
        return self.path_interface_map.get(path_id, f"Path {path_id}")
    
    def _parse_xquic_path_rtt(self, line):
        """Extract per-path RTT from xquic debug logs"""
        try:
            path_match = re.search(r'path_id:(\d+)', line)
            srtt_match = re.search(r'path_srtt:(\d+)', line)
            
            if path_match and srtt_match:
                path_id = int(path_match.group(1))
                srtt = int(srtt_match.group(1))
                
                # Try to extract full timestamp
                full_ts_match = re.search(r'now:(\d+)', line)
                if full_ts_match:
                    ts = int(full_ts_match.group(1))
                else:
                    ts = len(self.path_rtt_data[path_id])
                
                self.path_rtt_data[path_id].append({
                    'ts': ts,
                    'rtt': srtt
                })
        except Exception as e:
            pass
    
    def _parse_metrics(self, line):
        """Parse performance metrics"""
        try:
            json_str = re.search(r'\{.*\}', line).group()
            data = json.loads(json_str)
            
            path_id = data.get('path_id', 0)
            self.metrics[path_id].append({
                'ts': data['ts'],
                'send_bw': data['send_bw_mbps'],
                'recv_bw': data['recv_bw_mbps'],
                'loss_rate': data['loss_rate'],
                'rtt': data['rtt_us'],
                'is_active': data['is_active']
            })
        except Exception as e:
            pass
    
    def _merge_rtt_data(self):
        """Merge xquic RTT data into metrics"""
        for path_id, metrics in self.metrics.items():
            if path_id not in self.path_rtt_data:
                continue
            
            rtt_data = self.path_rtt_data[path_id]
            if not rtt_data:
                continue
            
            interface = self._get_path_label(path_id)
            print(f"  ✅ Found {len(rtt_data)} RTT data points for {interface}")
            
            for metric in metrics:
                closest = min(rtt_data, 
                            key=lambda x: abs(x['ts'] - metric['ts']),
                            default=None)
                if closest and closest['rtt'] > 0:
                    metric['rtt'] = closest['rtt']
    
    def _parse_event(self, line):
        """Parse events"""
        try:
            ts_match = re.search(r'ts:(\d+)', line)
            if ts_match:
                ts = int(ts_match.group(1))
                
                if 'PATH_CREATED' in line:
                    self.events.append({'ts': ts, 'type': 'PATH_CREATED'})
                elif 'PATH_REMOVED' in line:
                    self.events.append({'ts': ts, 'type': 'PATH_REMOVED'})
                elif 'REBINDING' in line:
                    self.events.append({'ts': ts, 'type': 'HANDOVER'})
                    self.handover_times.append(ts)
        except Exception as e:
            pass
    
    def print_summary(self):
        """Print summary statistics"""
        print("\n" + "="*60)
        print("Multipath Performance Analysis Summary")
        print("="*60)
        
        # Merge RTT data first
        print("\n🔄 Merging xquic internal RTT data...")
        self._merge_rtt_data()
        
        for path_id, data in self.metrics.items():
            if not data:
                continue
            
            interface = self._get_path_label(path_id)
            print(f"\n📊 {interface} Statistics:")
            print(f"  Sample points: {len(data)}")
            
            active_data = [d for d in data if d['is_active']]
            if active_data:
                avg_send = sum(d['send_bw'] for d in active_data) / len(active_data)
                avg_recv = sum(d['recv_bw'] for d in active_data) / len(active_data)
                avg_loss = sum(d['loss_rate'] for d in active_data) / len(active_data)
                
                # Calculate only non-zero RTT
                valid_rtt = [d['rtt'] for d in active_data if d['rtt'] > 0]
                if valid_rtt:
                    avg_rtt = sum(valid_rtt) / len(valid_rtt)
                    min_rtt = min(valid_rtt)
                    max_rtt = max(valid_rtt)
                    
                    print(f"  Avg Send Bandwidth: {avg_send:.2f} Mbps")
                    print(f"  Avg Recv Bandwidth: {avg_recv:.2f} Mbps")
                    print(f"  Avg Loss Rate: {avg_loss:.2f}%")
                    print(f"  Avg RTT: {avg_rtt/1000:.2f} ms")
                    print(f"  RTT Range: {min_rtt/1000:.2f} ~ {max_rtt/1000:.2f} ms")
                    print(f"  Valid RTT Points: {len(valid_rtt)}/{len(active_data)}")
                else:
                    print(f"  ⚠️  No valid RTT data found")
                    print(f"  Avg Send Bandwidth: {avg_send:.2f} Mbps")
                    print(f"  Avg Recv Bandwidth: {avg_recv:.2f} Mbps")
                    print(f"  Avg Loss Rate: {avg_loss:.2f}%")
                
                # Detect anomalies
                max_loss = max(d['loss_rate'] for d in active_data)
                
                if max_loss > 5:
                    print(f"  ⚠️  High packet loss detected: {max_loss:.2f}%")
                if valid_rtt and max(valid_rtt) > 100000:  # 100ms
                    print(f"  ⚠️  High latency detected: {max(valid_rtt)/1000:.2f} ms")
        
        print(f"\n📍 Key Events:")
        print(f"  Detected {len(self.handover_times)} handover(s)")
        
        if len(self.handover_times) > 0:
            self._analyze_handover_impact()
    
    def _analyze_handover_impact(self):
        """Analyze handover impact"""
        print(f"\n🔄 Handover Impact Analysis:")
        
        for i, ho_time in enumerate(self.handover_times):
            print(f"\n  Handover #{i+1} (timestamp: {ho_time})")
            
            for path_id, data in self.metrics.items():
                interface = self._get_path_label(path_id)
                before = [d for d in data if ho_time - 2000000 < d['ts'] < ho_time]
                after = [d for d in data if ho_time < d['ts'] < ho_time + 2000000]
                
                if before and after:
                    bw_before = sum(d['send_bw'] for d in before) / len(before)
                    bw_after = sum(d['send_bw'] for d in after) / len(after)
                    
                    loss_before = sum(d['loss_rate'] for d in before) / len(before)
                    loss_after = sum(d['loss_rate'] for d in after) / len(after)
                    
                    # RTT change analysis
                    rtt_before = [d['rtt'] for d in before if d['rtt'] > 0]
                    rtt_after = [d['rtt'] for d in after if d['rtt'] > 0]
                    
                    print(f"    {interface}:")
                    print(f"      Bandwidth: {bw_before:.2f} -> {bw_after:.2f} Mbps "
                          f"({((bw_after-bw_before)/bw_before*100) if bw_before > 0 else 0:.1f}%)")
                    print(f"      Loss Rate: {loss_before:.2f}% -> {loss_after:.2f}%")
                    
                    if rtt_before and rtt_after:
                        avg_rtt_before = sum(rtt_before) / len(rtt_before)
                        avg_rtt_after = sum(rtt_after) / len(rtt_after)
                        print(f"      RTT: {avg_rtt_before/1000:.2f} -> {avg_rtt_after/1000:.2f} ms")
    
    def plot_metrics(self, output_file='mp_analysis.png'):
        """Plot performance charts"""
        # Merge RTT data first
        self._merge_rtt_data()
        
        # ✅ Use English labels and better styling
        plt.rcParams['font.family'] = 'DejaVu Sans'
        plt.rcParams['font.size'] = 10
        
        fig, axes = plt.subplots(3, 1, figsize=(14, 10))
        
        all_ts = []
        for data in self.metrics.values():
            all_ts.extend([d['ts'] for d in data])
        
        if not all_ts:
            print("⚠️  Insufficient data for plotting")
            return
        
        start_ts = min(all_ts)
        
        # ✅ Color scheme for different interfaces
        colors = ['#2E86AB', '#A23B72', '#F18F01', '#C73E1D', '#6A994E']
        
        # Plot bandwidth
        ax1 = axes[0]
        for idx, (path_id, data) in enumerate(sorted(self.metrics.items())):
            interface = self._get_path_label(path_id)
            ts = [(d['ts'] - start_ts) / 1000000 for d in data]
            bw = [d['send_bw'] for d in data]
            ax1.plot(ts, bw, label=interface, marker='o', markersize=2, 
                    color=colors[idx % len(colors)], linewidth=1.5)
        
        ax1.set_ylabel('Bandwidth (Mbps)', fontsize=11, fontweight='bold')
        ax1.set_title('Multipath Bandwidth Over Time', fontsize=13, fontweight='bold', pad=15)
        ax1.legend(loc='best', framealpha=0.9)
        ax1.grid(True, alpha=0.3, linestyle='--')
        
        # Mark handover times
        for ho_time in self.handover_times:
            ho_sec = (ho_time - start_ts) / 1000000
            ax1.axvline(x=ho_sec, color='red', linestyle='--', alpha=0.6, 
                       linewidth=2, label='Handover' if ho_time == self.handover_times[0] else '')
        if self.handover_times:
            ax1.legend(loc='best', framealpha=0.9)
        
        # Plot packet loss
        ax2 = axes[1]
        for idx, (path_id, data) in enumerate(sorted(self.metrics.items())):
            interface = self._get_path_label(path_id)
            ts = [(d['ts'] - start_ts) / 1000000 for d in data]
            loss = [d['loss_rate'] for d in data]
            ax2.plot(ts, loss, label=interface, marker='o', markersize=2,
                    color=colors[idx % len(colors)], linewidth=1.5)
        
        ax2.set_ylabel('Packet Loss Rate (%)', fontsize=11, fontweight='bold')
        ax2.set_title('Packet Loss Rate Over Time', fontsize=13, fontweight='bold', pad=15)
        ax2.legend(loc='best', framealpha=0.9)
        ax2.grid(True, alpha=0.3, linestyle='--')
        
        for ho_time in self.handover_times:
            ho_sec = (ho_time - start_ts) / 1000000
            ax2.axvline(x=ho_sec, color='red', linestyle='--', alpha=0.6, linewidth=2)
        
        # Plot RTT
        ax3 = axes[2]
        has_valid_rtt = False
        
        for idx, (path_id, data) in enumerate(sorted(self.metrics.items())):
            interface = self._get_path_label(path_id)
            # Only plot non-zero RTT values
            valid_data = [(d['ts'], d['rtt']) for d in data if d['rtt'] > 0]
            
            if valid_data:
                has_valid_rtt = True
                ts = [(t - start_ts) / 1000000 for t, _ in valid_data]
                rtt = [r / 1000 for _, r in valid_data]  # Convert to ms
                ax3.plot(ts, rtt, label=interface, marker='o', markersize=2,
                        color=colors[idx % len(colors)], linewidth=1.5)
        
        if not has_valid_rtt:
            ax3.text(0.5, 0.5, 
                    '⚠️ No Valid RTT Data Detected\n'
                    'Hint: Check path_srtt field in xquic logs',
                    ha='center', va='center', transform=ax3.transAxes, 
                    fontsize=12, color='red', 
                    bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.5))
        else:
            ax3.set_xlabel('Time (seconds)', fontsize=11, fontweight='bold')
            ax3.set_ylabel('RTT (ms)', fontsize=11, fontweight='bold')
            ax3.set_title('Round-Trip Time (from xquic internal logs)', 
                         fontsize=13, fontweight='bold', pad=15)
            ax3.legend(loc='best', framealpha=0.9)
            ax3.grid(True, alpha=0.3, linestyle='--')
            
            for ho_time in self.handover_times:
                ho_sec = (ho_time - start_ts) / 1000000
                ax3.axvline(x=ho_sec, color='red', linestyle='--', alpha=0.6, linewidth=2)
        
        plt.tight_layout()
        plt.savefig(output_file, dpi=150, bbox_inches='tight')
        print(f"\n📊 Chart saved to: {output_file}")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <log_file>")
        sys.exit(1)
    
    analyzer = MPLogAnalyzer(sys.argv[1])
    print("🔍 Parsing log file...")
    analyzer.parse_log()
    
    if not analyzer.path_interface_map:
        print("⚠️  Warning: Could not detect interface mapping from logs")
        print("   Using default Path 0, Path 1 labels")
    
    analyzer.print_summary()
    analyzer.plot_metrics()