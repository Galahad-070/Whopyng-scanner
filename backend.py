from flask import Flask, request, render_template, Response
from flask_cors import CORS  # Import CORS
import threading
import queue
import sys
import io
from scanner import start_scan
import os
import signal

app = Flask(__name__)

# Enable CORS for all routes and origins
CORS(app)

output_queue = queue.Queue()

class QueueWriter:
    def __init__(self, queue):
        self.queue = queue

    def write(self, msg):

        for line in msg.strip().splitlines():
            if line.strip():
                self.queue.put(line)

    def flush(self):
        pass


def capture_output(ip, portScan, osDetect, vulnCheck):
    old_stdout = sys.stdout
    sys.stdout = QueueWriter(output_queue)

    try:
        start_scan(ip, portScan, osDetect, vulnCheck)
    finally:
        sys.stdout = old_stdout

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/start-scan', methods=['POST'])
def start_scan_request():
    data = request.json
    ip = data.get("ip")
    portScan = data.get("portScan")
    osDetect = data.get("osDetect")
    vulnCheck = data.get("vulnCheck")


    threading.Thread(target=capture_output, args=(ip, portScan, osDetect, vulnCheck)).start()

    return {"message": "Scan started!"}

@app.route('/stream')
def stream():
    def event_stream():
        while True:
            try:
                line = output_queue.get(timeout=30)
                yield f"data: {line}\n\n"
            except queue.Empty:
                break

    return Response(event_stream(), mimetype='text/event-stream')


@app.route('/exit', methods=['POST'])
def exit_scan():
    global scan_running
    scan_running = False

    os.kill(os.getpid(), signal.SIGINT)




if __name__ == '__main__':
    app.run(debug=False, threaded=True)
