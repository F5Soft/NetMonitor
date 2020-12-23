import ipaddress
import logging
import operator
from collections import defaultdict
from functools import reduce

from flask import Flask, request, render_template, jsonify

from monitor import Analyzer, Sniffer

app = Flask(__name__)

sn = Sniffer()
an = Analyzer()


@app.route('/', methods=['GET', 'POST'])
def index():
    global sn
    if request.method == 'GET':
        rarp_table = defaultdict(list)
        for mac, ip_set in sn.rarp_table.items():
            for ip in ip_set:
                rarp_table[mac].append(ip)
        for mac, ip6_set in sn.rarp_table6.items():
            for ip6 in ip6_set:
                rarp_table[mac].append(ip6)
        return render_template('index.html', title='基本信息配置', rarp_table=rarp_table, started=sn.started,
                               iface=sn.iface, ip=sn.ip, ip6=sn.ip6, mac=sn.mac, net=sn.net, net6=sn.net6,
                               router_ip=sn.router_ip, router_ip6=sn.router_ip6, router_mac=sn.router_mac,
                               target_ip=sn.target_ip, target_ip6=sn.target_ip6, target_mac=sn.target_mac)
    if request.method == 'POST' and request.args.get('act') == 'iface':
        iface = request.form.get('iface', '').strip()
        sn.stop()
        try:
            sn = Sniffer(iface)
        except:
            return jsonify(False)
        return jsonify(True)
    if request.method == 'POST' and request.args.get('act') == 'scan':
        timeout = int(request.form.get('timeout', '3').strip()) / 3
        sn.scan(timeout=timeout)
        sn.scan6(timeout=timeout)
        return jsonify(True)
    if request.method == 'POST' and request.args.get('act') == 'sniff':
        sn.stop()
        mac = request.form.get('mac', '').strip()
        interval = int(request.form.get('interval', '0').strip())
        sn.set(mac)
        sn.start(an.feed, spoof_interval=interval)
        return jsonify(True)


@app.route('/stats/', methods=['GET', 'POST'])
def stats():
    if request.method == 'GET':
        return render_template('stats.html', title='协议统计')
    if request.method == 'POST':
        return jsonify(an.stats)


@app.route('/packets/', methods=['GET', 'POST'])
def packets():
    if request.method == 'GET':
        return render_template('packets.html', title='报文信息')
    if request.method == 'POST':
        return jsonify(an.packets)


@app.route('/ban/', methods=['GET', 'POST'])
def ban():
    if request.method == 'GET':
        return render_template('ban.html', title='断网规则', ip_ban=an.ip_ban, domain_ban=an.domain_ban,
                               content_ban=an.content_ban, status=reduce(operator.or_, an.ban_status))
    if request.method == 'POST' and request.args.get('act') == 'ban':
        an.ban()
        return jsonify(True)
    if request.method == 'POST' and request.args.get('act') == 'unban':
        an.unban()
        return jsonify(True)
    if request.method == 'POST' and request.args.get('act') == 'rule':
        ip_ban = request.form.get('ip-ban', '').split(' ')
        domain_ban = request.form.get('domain-ban', '').split(' ')
        content_ban = request.form.get('content-ban', '').split(' ')
        an.ip_ban.clear()
        an.domain_ban.clear()
        an.content_ban.clear()
        for ip in ip_ban:
            ip = ip.strip()
            if ip != '':
                if '/' in ip:
                    try:
                        an.ip_ban.update(ipaddress.ip_network(ip, False).hosts())
                    except:
                        pass
                else:
                    an.ip_ban.add(ip)
        for domain in domain_ban:
            domain = domain.strip()
            if domain != '':
                an.domain_ban.add(domain)
        for content in content_ban:
            content = content.strip()
            if content != '':
                an.content_ban.add(content)
        return jsonify(True)
    if request.method == 'POST' and request.args.get('act') == 'method':
        return jsonify(an.ban_method)
    if request.method == 'POST' and request.args.get('act') in "01234":
        idx = int(request.args.get('act'))
        an.ban_method[idx] = not an.ban_method[idx]
        return jsonify(True)


@app.route('/usrinfo/', methods=['GET', 'POST'])
def usrinfo():
    if request.method == 'GET':
        return render_template('usrinfo.html', title='用户信息')
    if request.method == 'POST':
        ans = []
        for k, v in an.password.items():
            ans.append((k, v[0], v[1]))
        print(ans)
        return jsonify(ans)


if __name__ == '__main__':
    logging.getLogger('werkzeug').disabled = True
    app.run(host='0.0.0.0', port=80, debug=True, use_reloader=False)
