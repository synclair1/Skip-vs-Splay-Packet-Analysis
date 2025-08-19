from flask import Flask, render_template_string, request
from Rule_Set import Rule_Set
from Packet import Packet
from Skip_List import SkipList
from splaytree import SplayTree
import time
import plotly.graph_objs as go
from plotly.offline import plot

app = Flask(__name__)

SRC_IP_IDX = 1
DST_IP_IDX = 2
SRC_PORT_IDX = 3
DST_PORT_IDX = 4
PROTO_IDX = 5

def filter_packets(packets, rule_objs):
    return [
        pkt[0]
        for pkt in packets
        if all(rule.find(pkt[idx]) for rule, idx in rule_objs)
    ]

def protocol_search(packets_list, rule):
    times = []
    for packets in packets_list:
        start = time.time()
        [pkt[0] for pkt in packets if rule.find(pkt[PROTO_IDX])]
        end = time.time()
        times.append(end - start)
    return times

def time_and_filter(packets, rule_objs):
    start = time.time()
    filter_packets(packets, rule_objs)
    end = time.time()
    return end - start

def build_rules(rule_class, rules_dict):
    rule_obj = rule_class()
    for i, j in rules_dict.items():
        rule_obj.insert(int(i), j)
    return rule_obj

def run_analysis(dataset):
    if dataset == 'acl2':
        rules_path = "Data_set/acl2/acl2_8k/acl2-8k.txt"
        packet_paths = [
            "Data_set/acl2/acl2_8k/acl8k_header8k/skewness 0.txt",
            "Data_set/acl2/acl2_8k/acl8k_header32k/skewness 0.txt",
            "Data_set/acl2/acl2_8k/acl8k_header128/skewness 0.txt"
        ]
    else:  # ipc2
        rules_path = "Data_set/ip2/ipc2_8k/ipc2-8k.txt"
        packet_paths = [
            "Data_set/ip2/ipc2_8k/ipc8k_header8k/skewness 0.txt",
            "Data_set/ip2/ipc2_8k/ipc8k_header32k/skewness 0.txt",
            "Data_set/ip2/ipc2_8k/ipc8k_header128k/skewness 0.txt"
        ]

    rules = Rule_Set()
    rules.get_rules(rules_path)

    packet_8k = Packet()
    packet_8k.get_packets(packet_paths[0])
    packet_32k = Packet()
    packet_32k.get_packets(packet_paths[1])
    packet_128k = Packet()
    packet_128k.get_packets(packet_paths[2])

    packets_list = [packet_8k.packets, packet_32k.packets, packet_128k.packets]

    # Protocol Search
    skip_rules = SkipList()
    for i, j in rules.protocol.items():
        skip_rules.insert(i, j)
    skip_times = protocol_search(packets_list, skip_rules)

    splay_rules = SplayTree()
    for i, j in rules.protocol.items():
        splay_rules.insert(i, j)
    splay_times = protocol_search(packets_list, splay_rules)

    # IP Packet Search
    skip_rule_objs = [
        (build_rules(SkipList, rules.source_IP), SRC_IP_IDX),
        (build_rules(SkipList, rules.dest_IP), DST_IP_IDX),
        (build_rules(SkipList, rules.source_Port), SRC_PORT_IDX),
        (build_rules(SkipList, rules.dest_Port), DST_PORT_IDX),
        (build_rules(SkipList, rules.protocol), PROTO_IDX)
    ]
    skip_ip_times = []
    for packets in packets_list:
        elapsed = time_and_filter(packets, skip_rule_objs)
        skip_ip_times.append(elapsed)

    splay_rule_objs = [
        (build_rules(SplayTree, rules.source_IP), SRC_IP_IDX),
        (build_rules(SplayTree, rules.dest_IP), DST_IP_IDX),
        (build_rules(SplayTree, rules.source_Port), SRC_PORT_IDX),
        (build_rules(SplayTree, rules.dest_Port), DST_PORT_IDX),
        (build_rules(SplayTree, rules.protocol), PROTO_IDX)
    ]
    splay_ip_times = []
    for packets in packets_list:
        elapsed = time_and_filter(packets, splay_rule_objs)
        splay_ip_times.append(elapsed)

    return skip_times, splay_times, skip_ip_times, splay_ip_times

def create_plot(graph_type, skip_times, splay_times, skip_ip_times, splay_ip_times, dataset):
    x_vals = [8000, 32000, 128000]
    if graph_type == "protocol":
        fig = go.Figure()
        fig.add_trace(go.Scatter(x=x_vals, y=skip_times, mode='markers+lines', name='Skip List', marker=dict(color='red')))
        fig.add_trace(go.Scatter(x=x_vals, y=splay_times, mode='markers+lines', name='Splay Tree', marker=dict(color='blue')))
        fig.update_layout(
            title=f"Protocol Search ({dataset.upper()})",
            xaxis_title="Number of Packets",
            yaxis_title="Time (seconds)",
            plot_bgcolor='black',
            paper_bgcolor='black',
            font=dict(color='white')
        )
        description = f"This graph shows the time taken to filter packets by protocol using Skip List and Splay Tree structures for the {dataset.upper()} dataset."
    else:
        fig = go.Figure()
        fig.add_trace(go.Scatter(x=x_vals, y=skip_ip_times, mode='markers+lines', name='Skip List', marker=dict(color='red')))
        fig.add_trace(go.Scatter(x=x_vals, y=splay_ip_times, mode='markers+lines', name='Splay Tree', marker=dict(color='blue')))
        fig.update_layout(
            title=f"IP Packet Search ({dataset.upper()})",
            xaxis_title="Number of Packets",
            yaxis_title="Time (seconds)",
            plot_bgcolor='black',
            paper_bgcolor='black',
            font=dict(color='white')
        )
        description = f"This graph shows the time taken to filter packets by all five fields (IP, Port, Protocol) using Skip List and Splay Tree structures for the {dataset.upper()} dataset."
    plot_div = plot(fig, output_type='div', include_plotlyjs='cdn')
    return plot_div, description

@app.route('/', methods=['GET', 'POST'])
def index():
    graph_type = request.form.get('graph_type', 'protocol')
    dataset = request.form.get('dataset', 'acl2')
    skip_times, splay_times, skip_ip_times, splay_ip_times = run_analysis(dataset)
    plot_div, description = create_plot(graph_type, skip_times, splay_times, skip_ip_times, splay_ip_times, dataset)
    html = '''
    <html>
    <head>
        <title>Packet Filtering Analysis</title>
        <style>
            body {
                background-color: #000;
                color: #fff;
                font-family: Arial, sans-serif;
            }
            .container {
                width: 800px;
                margin: 40px auto;
                background: rgba(30,30,30,0.95);
                padding: 30px;
                border-radius: 15px;
                box-shadow: 0 0 20px #222;
            }
            h1, h2 {
                color: #fff;
                text-align: center;
            }
            .desc {
                margin: 20px 0;
                font-size: 1.1em;
                text-align: center;
            }
            .form-group {
                text-align: center;
                margin-bottom: 20px;
            }
            select, input[type=submit] {
                padding: 8px 16px;
                font-size: 1em;
                border-radius: 5px;
                border: none;
                margin: 0 5px;
            }
            select {
                background: #222;
                color: #fff;
            }
            input[type=submit] {
                background: #444;
                color: #fff;
                cursor: pointer;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Packet Filtering Analysis</h1>
            <form method="post" class="form-group">
                <label for="dataset">Select Dataset:</label>
                <select name="dataset" id="dataset">
                    <option value="acl2" {% if dataset == 'acl2' %}selected{% endif %}>ACL2</option>
                    <option value="ipc2" {% if dataset == 'ipc2' %}selected{% endif %}>IPC2</option>
                </select>
                <label for="graph_type">Select Graph:</label>
                <select name="graph_type" id="graph_type">
                    <option value="protocol" {% if graph_type == 'protocol' %}selected{% endif %}>Protocol Search</option>
                    <option value="ip" {% if graph_type == 'ip' %}selected{% endif %}>IP Packet Search</option>
                </select>
                <input type="submit" value="Show Graph">
            </form>
            <div class="desc">{{ description }}</div>
            {{ plot_div|safe }}
        </div>
    </body>
    </html>
    '''
    return render_template_string(html, plot_div=plot_div, graph_type=graph_type, dataset=dataset, description=description)

if __name__ == '__main__':
    app.run(debug=True)