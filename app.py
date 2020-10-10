import socket, struct
import threading
from flask import Flask, render_template
from flask_socketio import SocketIO, emit

app = Flask(__name__)
socketio = SocketIO(app)

app.config['TEMPLATES_AUTO_RELOAD'] = True

s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))

@app.route('/')
def index():
    return render_template('index.html')

def b2mac(bytes_addr):
    return ':'.join(map('{:02x}'.format, bytes_addr))

def socket_msg_collector():
    global socketio

    t = threading.currentThread()

    while t.loop:
        data, _ = s.recvfrom(65535)

        ethernet_header = data[:14]
        ip_header = data[14:34]
        tcp_header = data[34:54]

        dst_mac, src_mac, _ = struct.unpack('!6s6s2s', ethernet_header)
        _, src_ip, dst_ip = struct.unpack('!12s4s4s', ip_header)
        src_port, dst_port, _ = struct.unpack('!HH16s', tcp_header)

        print('{} > {} {}:{} > {}:{}'.format(b2mac(src_mac), b2mac(dst_mac), socket.inet_ntoa(src_ip), src_port, socket.inet_ntoa(dst_ip), dst_port))

        socketio.emit('message', {
            'src_mac': b2mac(src_mac), 'dst_mac': b2mac(dst_mac),
            'src_ip': socket.inet_ntoa(src_ip),
            'src_port': src_port,
            'dst_ip': socket.inet_ntoa(dst_ip),
            'dst_port': dst_port
            })

socket_msg_thread = threading.Thread(target=socket_msg_collector)

def main():
    socket_msg_thread.loop = True
    socket_msg_thread.start()
    socketio.run(app=app, host='0.0.0.0')

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        socketio.stop()
        socket_msg_thread.loop = False

