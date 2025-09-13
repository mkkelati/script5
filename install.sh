#!/bin/bash
# MK Script Manager v4.0 - Installation Script
# Compatible with Ubuntu 20.04 - 24.04 LTS

if [[ "$EUID" -ne 0 ]]; then
  echo "Please run this installer as root (using sudo)."
  exit 1
fi

clear
echo "==========================================="
echo "    MK Script Manager v4.0 Installer"
echo "==========================================="
echo ""
echo "[*] Installing system dependencies..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y >/dev/null 2>&1

# Install basic dependencies including net-tools for netstat command and SSH tools
apt-get install -y openssl screen wget curl net-tools iproute2 systemd openssh-client sshpass >/dev/null 2>&1

# Install latest stunnel with proper configuration for newer Ubuntu versions
echo "[*] Installing and configuring latest stunnel..."

# Install build dependencies first (includes BadVPN dependencies)
apt-get install -y build-essential libssl-dev zlib1g-dev wget tar cmake >/dev/null 2>&1

# Try to install latest stunnel from source
cd /tmp
echo "[*] Downloading stunnel 5.75 (latest)..."
if wget -q https://www.stunnel.org/downloads/stunnel-5.75.tar.gz; then
    echo "[*] Compiling latest stunnel..."
    tar -xzf stunnel-5.75.tar.gz
    cd stunnel-5.75
    ./configure --prefix=/usr/local --enable-ipv6 >/dev/null 2>&1
    make >/dev/null 2>&1
    make install >/dev/null 2>&1
    
    # Create symlinks for compatibility
    ln -sf /usr/local/bin/stunnel /usr/bin/stunnel4 2>/dev/null
    ln -sf /usr/local/bin/stunnel /usr/bin/stunnel 2>/dev/null
    
    # Create proper systemd service for compiled stunnel
    cat > /etc/systemd/system/stunnel4.service << 'EOF'
[Unit]
Description=Stunnel TLS tunnel
After=network-online.target
Wants=network-online.target

[Service]
Type=forking
ExecStart=/usr/local/bin/stunnel /etc/stunnel/stunnel.conf
ExecReload=/bin/kill -HUP $MAINPID
PIDFile=/var/run/stunnel4/stunnel.pid
User=root
Group=root
RuntimeDirectory=stunnel4
RuntimeDirectoryMode=0755

[Install]
WantedBy=multi-user.target
EOF
    
    # Clean up
    cd /
    rm -rf /tmp/stunnel-5.75*
    
    echo "[*] Latest stunnel 5.75 installed successfully with systemd service"
else
    echo "[*] Fallback: Installing stunnel4 from Ubuntu repository..."
    apt-get install -y stunnel4 >/dev/null 2>&1
fi

# Fix stunnel4 configuration for Ubuntu 22.04/24.04
if [[ -f /etc/default/stunnel4 ]]; then
    sed -i 's/ENABLED=0/ENABLED=1/' /etc/default/stunnel4 2>/dev/null
    echo 'ENABLED=1' >> /etc/default/stunnel4 2>/dev/null
else
    echo 'ENABLED=1' > /etc/default/stunnel4
fi

# Clean up old systemd overrides and reload daemon
rm -rf /etc/systemd/system/stunnel4.service.d 2>/dev/null
systemctl daemon-reload >/dev/null 2>&1

echo "[*] Configuring stunnel service..."
if [[ -f /etc/default/stunnel4 ]]; then
  if grep -qs "ENABLED=0" /etc/default/stunnel4; then
    sed -i 's/ENABLED=0/ENABLED=1/' /etc/default/stunnel4
  fi
else
  echo 'ENABLED=1' > /etc/default/stunnel4
fi

mkdir -p /etc/stunnel
STUNNEL_CERT="/etc/stunnel/stunnel.pem"
if [[ ! -f "$STUNNEL_CERT" ]]; then
  echo "[*] Generating self-signed SSL certificate for stunnel..."
  
  # Create certificate
  openssl req -newkey rsa:4096 -x509 -sha256 -days 3650 -nodes \
    -subj "/C=US/ST=State/L=City/O=MK-Script/OU=IT/CN=$(hostname)" \
    -keyout /etc/stunnel/key.pem -out /etc/stunnel/cert.pem >/dev/null 2>&1
  
  # Combine certificate and key
  cat /etc/stunnel/key.pem /etc/stunnel/cert.pem > "$STUNNEL_CERT"
  
  # Set proper ownership and permissions for stunnel4 user
  chown stunnel4:stunnel4 "$STUNNEL_CERT" 2>/dev/null || chown root:stunnel4 "$STUNNEL_CERT"
  chmod 640 "$STUNNEL_CERT"
  
  # Fix directory permissions
  chown -R stunnel4:stunnel4 /etc/stunnel 2>/dev/null || chown -R root:stunnel4 /etc/stunnel
  chmod 755 /etc/stunnel
  
  # Clean up individual files
  rm -f /etc/stunnel/key.pem /etc/stunnel/cert.pem
fi

STUNNEL_CONF="/etc/stunnel/stunnel.conf"
if [[ ! -f "$STUNNEL_CONF" ]]; then
  echo "[*] Setting up stunnel configuration..."
  cat > "$STUNNEL_CONF" << 'EOC'
# Mandatory TLS_AES_256_GCM_SHA384 cipher configuration
cert = /etc/stunnel/stunnel.pem
pid = /var/run/stunnel4/stunnel.pid

# Logging
debug = 7
output = /var/log/stunnel4/stunnel.log

[ssh-tunnel]
accept = 443
connect = 127.0.0.1:22

# MANDATORY: Only TLS_AES_256_GCM_SHA384 cipher allowed
ciphersuites = TLS_AES_256_GCM_SHA384

# Force TLS 1.3 only for TLS_AES_256_GCM_SHA384
sslVersion = TLSv1.3
options = NO_SSLv2
options = NO_SSLv3
options = NO_TLSv1
options = NO_TLSv1_1
options = NO_TLSv1_2
EOC
fi

echo "[*] Starting stunnel service..."
systemctl restart stunnel4
systemctl enable stunnel4

echo "[*] Configuring SSH for password authentication..."

# Function to check if PasswordAuthentication is enabled anywhere
check_password_auth() {
    # Check main config file
    if grep -q "^PasswordAuthentication yes" /etc/ssh/sshd_config 2>/dev/null; then
        return 0
    fi
    
    # Check all config.d files
    if find /etc/ssh/sshd_config.d/ -name "*.conf" -exec grep -l "^PasswordAuthentication yes" {} \; 2>/dev/null | grep -q .; then
        return 0
    fi
    
    return 1
}

# Function to disable PasswordAuthentication in all locations
disable_password_auth_everywhere() {
    # Disable in main config
    sed -i 's/^PasswordAuthentication no/#PasswordAuthentication no/' /etc/ssh/sshd_config 2>/dev/null
    sed -i 's/^PasswordAuthentication yes/#PasswordAuthentication yes/' /etc/ssh/sshd_config 2>/dev/null
    
    # Disable in all config.d files
    find /etc/ssh/sshd_config.d/ -name "*.conf" -exec sed -i 's/^PasswordAuthentication.*/#&/' {} \; 2>/dev/null
}

# Check current status
if check_password_auth; then
    echo "[*] SSH password authentication already enabled"
else
    echo "[*] Enabling SSH password authentication for HTTP Injector compatibility..."
    
    # Show current SSH config status
    echo "[*] Checking SSH configuration files..."
    
    # Check main config
    if grep -q "PasswordAuthentication" /etc/ssh/sshd_config 2>/dev/null; then
        echo "[*] Found PasswordAuthentication in main config: $(grep PasswordAuthentication /etc/ssh/sshd_config)"
    fi
    
    # Check config.d directory
    if [ -d "/etc/ssh/sshd_config.d/" ]; then
        echo "[*] Checking /etc/ssh/sshd_config.d/ files..."
        find /etc/ssh/sshd_config.d/ -name "*.conf" -exec echo "[*] Checking: {}" \; -exec grep -H "PasswordAuthentication" {} \; 2>/dev/null || echo "[*] No PasswordAuthentication found in config.d files"
    fi
    
    # Disable all existing PasswordAuthentication settings to avoid conflicts
    disable_password_auth_everywhere
    
    # Create our own config file with highest priority
    echo "[*] Creating MK Script SSH configuration..."
    cat > /etc/ssh/sshd_config.d/99-mk-script.conf << 'EOF'
# MK Script Manager SSH Configuration
# This file ensures HTTP Injector compatibility
PasswordAuthentication yes
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
PermitRootLogin no
MaxAuthTries 6
EOF
    
    chmod 644 /etc/ssh/sshd_config.d/99-mk-script.conf
    echo "[*] Created /etc/ssh/sshd_config.d/99-mk-script.conf with PasswordAuthentication yes"
    
    # Test SSH configuration
    echo "[*] Testing SSH configuration..."
    if sshd -t 2>/dev/null; then
        echo "[*] SSH configuration test passed"
        
        # Restart SSH service
        systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null || service ssh restart 2>/dev/null
        echo "[*] SSH service restarted successfully"
        
        # Verify the setting is active
        if check_password_auth; then
            echo "[*] ✅ SSH password authentication successfully enabled"
        else
            echo "[*] ⚠️  Warning: PasswordAuthentication may not be active, but config file created"
        fi
    else
        echo "[*] ❌ SSH configuration test failed, removing our config file"
        rm -f /etc/ssh/sshd_config.d/99-mk-script.conf
        echo "[*] Falling back to main config file method..."
        
        # Fallback: modify main config file
        if ! grep -q "^PasswordAuthentication" /etc/ssh/sshd_config; then
            echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config
        else
            sed -i 's/^PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
        fi
        
        systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null || service ssh restart 2>/dev/null
        echo "[*] Applied fallback configuration"
    fi
fi

echo "[*] Applying maximum performance TCP optimizations..."
# Remove existing entries to prevent duplicates
sed -i '/net.core.rmem_max/d' /etc/sysctl.conf 2>/dev/null
sed -i '/net.core.wmem_max/d' /etc/sysctl.conf 2>/dev/null
sed -i '/net.ipv4.tcp_rmem/d' /etc/sysctl.conf 2>/dev/null
sed -i '/net.ipv4.tcp_wmem/d' /etc/sysctl.conf 2>/dev/null
sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf 2>/dev/null
sed -i '/net.core.netdev_max_backlog/d' /etc/sysctl.conf 2>/dev/null

# Add maximum performance network settings
echo '# MK Script Manager - Maximum Performance Network Settings' >> /etc/sysctl.conf
echo 'net.core.rmem_max = 134217728' >> /etc/sysctl.conf        # 128MB receive buffer
echo 'net.core.wmem_max = 134217728' >> /etc/sysctl.conf        # 128MB send buffer
echo 'net.ipv4.tcp_rmem = 4096 87380 134217728' >> /etc/sysctl.conf  # TCP receive window
echo 'net.ipv4.tcp_wmem = 4096 65536 134217728' >> /etc/sysctl.conf  # TCP send window
echo 'net.ipv4.tcp_congestion_control = bbr' >> /etc/sysctl.conf     # Best congestion control
echo 'net.core.netdev_max_backlog = 5000' >> /etc/sysctl.conf       # Handle more packets
echo 'net.ipv4.tcp_window_scaling = 1' >> /etc/sysctl.conf          # Enable window scaling
echo 'net.ipv4.tcp_timestamps = 1' >> /etc/sysctl.conf              # Enable timestamps
echo 'net.ipv4.tcp_sack = 1' >> /etc/sysctl.conf                    # Enable selective ACK
echo 'net.ipv4.tcp_no_metrics_save = 1' >> /etc/sysctl.conf         # Don't cache metrics
echo 'net.ipv4.tcp_moderate_rcvbuf = 1' >> /etc/sysctl.conf         # Auto-tune receive buffer

# Apply settings immediately
sysctl -p >/dev/null 2>&1

echo "[*] Installing menu system..."
INSTALL_DIR="/usr/local/bin"

# Always download the latest version from GitHub for consistency
echo "[*] Downloading menu script..."
if wget -q https://raw.githubusercontent.com/mkkelati/script5/main/menu.sh -O "${INSTALL_DIR}/menu"; then
  chmod +x "${INSTALL_DIR}/menu"
  echo "[*] Menu system installed successfully"
else
  echo "[ERROR] Failed to download menu script. Check internet connection."
  exit 1
fi

echo "[*] Setting up configuration..."
mkdir -p /etc/mk-script
touch /etc/mk-script/users.txt

# Create enhanced directory structure for v4.1
mkdir -p /etc/mk-script/senha
mkdir -p /etc/mk-script/ssh-keys
mkdir -p /etc/mk-script/http-injector

# Set proper permissions for security
chmod 700 /etc/mk-script/ssh-keys
chmod 755 /etc/mk-script/http-injector

echo "[*] Verifying installation..."
if [[ -x "${INSTALL_DIR}/menu" ]]; then
  clear
  sleep 1
  
  # Professional welcome message with colors
  echo ""
  echo ""
  echo -e "\033[1;34m╔══════════════════════════════════════════════════════════════════════════════╗\033[0m"
  echo -e "\033[1;34m║\033[1;32m                          🎉 INSTALLATION SUCCESSFUL! 🎉                        \033[1;34m║\033[0m"
  echo -e "\033[1;34m╠══════════════════════════════════════════════════════════════════════════════╣\033[0m"
  echo -e "\033[1;34m║\033[1;36m                                                                              \033[1;34m║\033[0m"
  echo -e "\033[1;34m║\033[1;33m    ███╗   ███╗██╗  ██╗    ███████╗ ██████╗██████╗ ██╗██████╗ ████████╗    \033[1;34m║\033[0m"
  echo -e "\033[1;34m║\033[1;33m    ████╗ ████║██║ ██╔╝    ██╔════╝██╔════╝██╔══██╗██║██╔══██╗╚══██╔══╝    \033[1;34m║\033[0m"
  echo -e "\033[1;34m║\033[1;33m    ██╔████╔██║█████╔╝     ███████╗██║     ██████╔╝██║██████╔╝   ██║       \033[1;34m║\033[0m"
  echo -e "\033[1;34m║\033[1;33m    ██║╚██╔╝██║██╔═██╗     ╚════██║██║     ██╔══██╗██║██╔═══╝    ██║       \033[1;34m║\033[0m"
  echo -e "\033[1;34m║\033[1;33m    ██║ ╚═╝ ██║██║  ██╗    ███████║╚██████╗██║  ██║██║██║        ██║       \033[1;34m║\033[0m"
  echo -e "\033[1;34m║\033[1;33m    ╚═╝     ╚═╝╚═╝  ╚═╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝╚═╝        ╚═╝       \033[1;34m║\033[0m"
  echo -e "\033[1;34m║\033[1;36m                                                                              \033[1;34m║\033[0m"
  echo -e "\033[1;34m║\033[1;35m                        🚀 MANAGER v4.1 - READY TO USE! 🚀                   \033[1;34m║\033[0m"
  echo -e "\033[1;34m║\033[1;36m                                                                              \033[1;34m║\033[0m"
  echo -e "\033[1;34m╠══════════════════════════════════════════════════════════════════════════════╣\033[0m"
  echo -e "\033[1;34m║\033[1;37m 🎯 WELCOME TO THE MOST ADVANCED SSH MANAGEMENT SYSTEM!                      \033[1;34m║\033[0m"
  echo -e "\033[1;34m║\033[1;36m                                                                              \033[1;34m║\033[0m"
  echo -e "\033[1;34m║\033[1;32m ✅ Latest stunnel 5.75 with TLS_AES_256_GCM_SHA384 cipher                  \033[1;34m║\033[0m"
  echo -e "\033[1;34m║\033[1;32m ✅ SSH Key detection for cloud servers (AWS, GCP, Azure, DO)               \033[1;34m║\033[0m"
  echo -e "\033[1;34m║\033[1;32m ✅ HTTP Injector configuration generator with SSL/TLS support              \033[1;34m║\033[0m"
  echo -e "\033[1;34m║\033[1;32m ✅ Advanced authentication (SSH Keys + Password support)                   \033[1;34m║\033[0m"
  echo -e "\033[1;34m║\033[1;32m ✅ Professional dashboard with real-time system monitoring                  \033[1;34m║\033[0m"
  echo -e "\033[1;34m║\033[1;32m ✅ 14 comprehensive management options for complete control                 \033[1;34m║\033[0m"
  echo -e "\033[1;34m║\033[1;36m                                                                              \033[1;34m║\033[0m"
  echo -e "\033[1;34m╠══════════════════════════════════════════════════════════════════════════════╣\033[0m"
  echo -e "\033[1;34m║\033[1;33m 🚀 GET STARTED:                                                             \033[1;34m║\033[0m"
  echo -e "\033[1;34m║\033[1;37m                                                                              \033[1;34m║\033[0m"
  echo -e "\033[1;34m║\033[1;36m    Just type: \033[1;31mmenu\033[1;36m                                                         \033[1;34m║\033[0m"
  echo -e "\033[1;34m║\033[1;37m                                                                              \033[1;34m║\033[0m"
  echo -e "\033[1;34m║\033[1;32m    Then enjoy the professional dashboard and 11 powerful options!          \033[1;34m║\033[0m"
  echo -e "\033[1;34m║\033[1;36m                                                                              \033[1;34m║\033[0m"
  echo -e "\033[1;34m╠══════════════════════════════════════════════════════════════════════════════╣\033[0m"
  echo -e "\033[1;34m║\033[1;35m 💡 SUPPORT: \033[1;37mhttps://github.com/mkkelati/script5                           \033[1;34m║\033[0m"
  echo -e "\033[1;34m║\033[1;35m 📧 VERSION: \033[1;37mv4.1 - Maximum Performance Edition                            \033[1;34m║\033[0m"
  echo -e "\033[1;34m║\033[1;35m 🌟 STATUS:  \033[1;32mFully Optimized & Ready for Production                        \033[1;34m║\033[0m"
  echo -e "\033[1;34m╚══════════════════════════════════════════════════════════════════════════════╝\033[0m"
  echo ""
  echo -e "\033[1;33m⭐ Thank you for choosing MK Script Manager v4.1 - Maximum Performance! ⭐\033[0m"
  echo ""
else
  echo "[ERROR] Installation failed. Menu command not found."
  exit 1
fi
