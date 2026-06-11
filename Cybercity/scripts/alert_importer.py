import json
import sqlite3
import time

from datetime import datetime

DB = "/opt/cybercity/db/cybercity.db"
LOG = "/opt/cybercity/zeek/logs/notice.log"

conn = sqlite3.connect(DB)
cursor = conn.cursor()

with open(LOG, "r") as f:

    #
    # Start at end of file
    #

    f.seek(0, 2)

    while True:

        line = f.readline()

        if not line:

            time.sleep(1)
            continue

        try:

            data = json.loads(line)

            #
            # Convert Zeek timestamp
            #

            ts = float(
                data.get("ts", 0)
            )

            timestamp = (
                datetime
                .utcfromtimestamp(ts)
                .strftime(
                    "%Y-%m-%d %H:%M:%S UTC"
                )
            )

            #
            # Alert fields
            #

            alert_type = str(
                data.get("note", "")
            )

            src_ip = str(
                data.get("src", "")
            )

            dst_ip = str(
                data.get("dst", "")
            )

            dst_port = str(
                data.get("p", "")
            )

            message = str(
                data.get("msg", "")
            )

            #
            # Insert into SQLite
            #

            cursor.execute(

                '''
                INSERT INTO alerts
                (
                    timestamp,
                    note,
                    src_ip,
                    dst_ip,
                    port,
                    message
                )

                VALUES (?, ?, ?, ?, ?, ?)
                ''',

                (
                    timestamp,
                    alert_type,
                    src_ip,
                    dst_ip,
                    dst_port,
                    message
                )

            )

            conn.commit()

            print(
                f"[+] ALERT INSERTED: "
                f"{alert_type}"
            )

        except Exception as e:

            print(
                f"[ERROR] {e}"
            )
