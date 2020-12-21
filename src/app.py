from flask import *

from monitor.analyze import Analyzer
from monitor.analyze import info
from monitor.sniff import Sniffer
from monitor.target import Target

app = Flask(__name__)

sn = Sniffer()
an = Analyzer()


@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'GET':
        return render_template('index.html', title='基本信息配置', iff_ip=sn.iff_ip, iff_ip6=sn.iff_ip6, iff_mac=sn.iff_mac,
                               router_ip=sn.router_ip, router_ip6=sn.router_ip6, router_mac=sn.router_mac)
    else:
        ip = request.form.get('ip')
        ip6 = request.form.get('ip6')
        Target.set(ip, ip6)


@app.route('/scan', methods=['POST'])
def scan():
    result = dict()
    net = request.form.get('net', '').strip()
    net6 = request.form.get('net6', '').strip()
    if net != '':
        result.update(sn.scan(net))
    if net6 != '':
        result.update(sn.scan6(net6))
    return jsonify(result)


@app.route('/sniff', methods=['POST'])
def sniff():
    if sn.started:
        return jsonify(False)
    ip = request.form.get('ip', '').strip()
    ip6 = request.form.get('ip6', '').strip()
    Target.set(ip, ip6)
    sn.start(an.feed)
    return jsonify(True)


@app.route('/stats', methods=['GET', 'POST'])
def stats():
    if request.method == 'GET':
        return render_template('stats.html', title='流量监控', cnt=an.cnt)
    elif request.method == 'POST':
        return jsonify(an.cnt)
    return render_template('stats.html', cnt=an.cnt)


@app.route('/detail', methods=['GET', 'POST'])
def detail():
    if request.method == 'GET':
        return render_template('detail.html', title='数据报文解析')
    elif request.method == 'POST':
        return jsonify(info)


@app.route('/ban', methods=['GET', 'POST'])
def ban():
    if request.method == 'GET':
        return render_template('ban.html', title='流量管理')
    elif request.method == 'POST':
        domain_ban = request.form.get('domain_ban', None)
        word_ban = request.form.get('word_ban', None)


if __name__ == '__main__':
    app.run(debug=True, use_reloader=False)
