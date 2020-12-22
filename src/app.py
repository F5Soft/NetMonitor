import logging
from collections import defaultdict

from flask import Flask, request, render_template, jsonify

from monitor import Analyzer, Sniffer

app = Flask(__name__)

sn = Sniffer('WLAN')
an = Analyzer()


@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'GET':
        rarp_table = defaultdict(list)
        for mac, ip_set in sn.rarp_table.items():
            for ip in ip_set:
                rarp_table[mac].append(ip)
        for mac, ip6_set in sn.rarp_table6.items():
            for ip6 in ip6_set:
                rarp_table[mac].append(ip6)
        return render_template('index.html', title='基本信息配置', rarp_table=rarp_table, started=sn.started,
                               ip=sn.ip, ip6=sn.ip6, mac=sn.mac, net=sn.net, net6=sn.net6,
                               router_ip=sn.router_ip, router_ip6=sn.router_ip6, router_mac=sn.router_mac,
                               target_ip=sn.target_ip, target_ip6=sn.target_ip6, target_mac=sn.target_mac)
    if request.method == 'POST' and request.args.get('act') == 'scan':
        timeout = int(request.form.get('timeout', '3')) / 3
        sn.scan(timeout=timeout)
        sn.scan6(timeout=timeout)
        return jsonify(True)
    if request.method == 'POST' and request.args.get('act') == 'sniff':
        if sn.started:
            sn.stop()
            return jsonify(False)
        else:
            mac = request.form.get('mac', '').strip()
            interval = int(request.form.get('interval', '0').strip())
            sn.set(mac)
            sn.start(an.feed, spoof_interval=interval)
            return jsonify(True)


@app.route('/stats', methods=['GET', 'POST'])
def stats():
    if request.method == 'GET':
        return render_template('stats.html', title='协议统计')
    elif request.method == 'POST':
        return jsonify(an.stats)


@app.route('/detail', methods=['GET', 'POST'])
def detail():
    if request.method == 'GET':
        return render_template('detail.html', title='数据报文解析')
    elif request.method == 'POST':
        return jsonify(an.info)


@app.route('/ban', methods=['GET', 'POST'])
def ban():
    if request.method == 'GET':
        return render_template('ban.html', title='流量管理')
    elif request.method == 'POST':
        domain_ban = request.form.get('domain_ban', None)
        word_ban = request.form.get('word_ban', None)


@app.route('/usrinfo', methods=['GET', 'POST'])
def usrinfo():
    if request.method == 'GET':
        return render_template('usrinfo.html', title='个人信息')
    elif request.method == 'POST':
        ans = []
        for k, v in an.password.items():
            ans.append((k, v[0], v[1]))
        print(ans)
        return jsonify(ans)


if __name__ == '__main__':
    logging.getLogger('werkzeug').disabled = True
    app.run(debug=True, use_reloader=False)
