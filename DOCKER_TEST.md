# Testing Honeypot with Docker

This guide shows you how to test the honeypot using Docker containers to simulate attackers from different "machines".

## Prerequisites

```bash
# Check if Docker is installed
docker --version

# If not installed:
sudo apt update
sudo apt install docker.io -y
sudo systemctl start docker
sudo usermod -aG docker $USER
# Log out and back in for group changes
```

## Method 1: Quick Test with Alpine Linux

### Step 1: Start the Honeypot

```bash
cd /home/parallels/scripts/auth-honeypot-framework
source venv/bin/activate
python src/main.py
```

Keep this running in one terminal.

### Step 2: Get Your Host IP

In another terminal:

```bash
# Get your Kali VM's IP (Docker containers will use this)
hostname -I | awk '{print $1}'
```

Let's say it shows: `192.168.1.100`

### Step 3: Run Attack from Docker

```bash
# Start an Alpine container
docker run -it --rm alpine sh

# Inside the container, install tools
apk add openssh-client ftp-client

# Try SSH attacks (replace with your IP)
ssh admin@192.168.1.100 -p 2222
# Enter any password when prompted

ssh root@192.168.1.100 -p 2222
# Enter any password

# Exit the container
exit
```

### Step 4: Check Honeypot Logs

```bash
cd /home/parallels/scripts/auth-honeypot-framework

# View the captured attacks
cat logs/attacks_$(date +%Y%m%d).json | jq .
```

You'll see the Docker container's IP and the credentials it tried!

---

## Method 2: Automated Attack Container

### Create Attack Script for Docker

Create `docker_attack.sh`:

```bash
#!/bin/sh
# This runs INSIDE a Docker container

echo "Starting automated attack simulation..."

TARGET_IP=$1
SSH_PORT=${2:-2222}

echo "Target: $TARGET_IP:$SSH_PORT"

# Install required tools
apk add --no-cache openssh-client sshpass 2>/dev/null

USERNAMES="admin root user test administrator"
PASSWORDS="admin password 123456 test root"

echo "Testing SSH honeypot..."

for user in $USERNAMES; do
    for pass in $PASSWORDS; do
        echo "Trying $user:$pass"
        sshpass -p "$pass" ssh -o StrictHostKeyChecking=no \
            -o ConnectTimeout=3 \
            $user@$TARGET_IP -p $SSH_PORT "echo test" 2>/dev/null
        sleep 0.5
    done
done

echo "Attack simulation complete!"
```

### Run the Attack Container

```bash
# Get your IP
HOST_IP=$(hostname -I | awk '{print $1}')

# Run attacker container
docker run -it --rm -v $(pwd)/docker_attack.sh:/attack.sh alpine sh /attack.sh $HOST_IP 2222
```

---

## Method 3: Multiple Simultaneous Attackers

Simulate multiple attackers hitting your honeypot at once:

```bash
#!/bin/bash
# run_multiple_attackers.sh

HOST_IP=$(hostname -I | awk '{print $1}')

echo "Launching 5 simultaneous attacker containers..."

for i in {1..5}; do
    echo "Starting attacker $i..."
    docker run -d --rm --name attacker_$i alpine sh -c "
        apk add --no-cache openssh-client >/dev/null 2>&1
        for j in {1..5}; do
            ssh -o StrictHostKeyChecking=no \
                -o ConnectTimeout=2 \
                attacker${i}@${HOST_IP} -p 2222 2>/dev/null
            sleep 1
        done
    " &
done

wait

echo "All attackers finished!"
echo "Check your honeypot logs to see all the attacks"
```

---

## Method 4: Hydra Attack Simulation (Advanced)

Use the professional security tool Hydra from Docker:

```bash
# Get your IP
HOST_IP=$(hostname -I | awk '{print $1}')

# Create password list
cat > passwords.txt << EOF
admin
password
123456
root
test
letmein
EOF

# Create username list
cat > usernames.txt << EOF
admin
root
user
test
administrator
EOF

# Run Hydra from Docker
docker run --rm -v $(pwd):/data vanhauser/hydra \
    -L /data/usernames.txt \
    -P /data/passwords.txt \
    -t 4 \
    ssh://${HOST_IP}:2222

# Check your honeypot logs - you'll see all these attempts!
```

---

## Method 5: Docker Compose - Honeypot + Attacker

Create `docker-compose.yml`:

```yaml
version: '3'
services:
  attacker:
    image: alpine:latest
    command: >
      sh -c "
      apk add --no-cache openssh-client &&
      while true; do
        ssh -o StrictHostKeyChecking=no \
            -o ConnectTimeout=2 \
            testuser@host.docker.internal -p 2222 2>/dev/null
        sleep 5
      done
      "
    extra_hosts:
      - "host.docker.internal:host-gateway"
```

Run it:
```bash
docker-compose up
```

This creates a continuous attacker that tries to connect every 5 seconds!

---

## Viewing Results in Real-Time

### Terminal 1: Run Honeypot
```bash
cd /home/parallels/scripts/auth-honeypot-framework
source venv/bin/activate
python src/main.py
```

### Terminal 2: Watch Logs
```bash
cd /home/parallels/scripts/auth-honeypot-framework
watch -n 1 'tail -5 logs/attacks_$(date +%Y%m%d).json'
```

### Terminal 3: Run Docker Attacks
```bash
# Run any of the methods above
```

You'll see attacks appear in real-time in Terminal 2!

---

## Analyze Captured Data

After running attacks:

```bash
cd /home/parallels/scripts/auth-honeypot-framework
source venv/bin/activate

# Count total attacks
cat logs/attacks_$(date +%Y%m%d).json | wc -l

# See unique IPs that attacked
cat logs/attacks_$(date +%Y%m%d).json | jq -r '.source_ip' | sort -u

# See most common usernames
cat logs/attacks_$(date +%Y%m%d).json | jq -r '.username' | sort | uniq -c | sort -rn

# See most common passwords
cat logs/attacks_$(date +%Y%m%d).json | jq -r '.password' | sort | uniq -c | sort -rn

# Generate full report
python3 << 'EOF'
from src.core.analyzer import AttackAnalyzer
from src.core.reporter import Reporter
import yaml

with open('config.yaml') as f:
    config = yaml.safe_load(f)

analyzer = AttackAnalyzer('logs')
analysis = analyzer.analyze(days=1)
print(analyzer.get_summary(analysis))

reporter = Reporter(config)
reporter.generate_report(days=1, formats=['json', 'html', 'text'])
EOF
```

---

## Clean Up

Stop all attack containers:
```bash
docker stop $(docker ps -q --filter name=attacker)
```

Stop the honeypot:
```bash
# Press Ctrl+C in the honeypot terminal
```

---

## Next Level: Internet-Facing Honeypot

**Warning:** Only do this if you understand the security implications!

1. Deploy honeypot on a VPS (DigitalOcean, AWS, etc.)
2. Open ports 2222, 2121, 2323 in firewall
3. Wait 24 hours
4. You'll capture REAL attack data from actual attackers!

Expect:
- Hundreds/thousands of attempts per day
- Attackers from around the world
- Real credential lists used by botnets
- Actual attack patterns and tools

This is where the honeypot becomes truly valuable for threat intelligence!
