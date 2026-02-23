#!/bin/bash
# Install TakeoverHunter dependencies on Parrot OS

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║     🎯 TAKEOVERHUNTER v1.0 - DEPENDENCY INSTALLER           ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Check if running as root
if [ "$EUID" -eq 0 ]; then 
   echo -e "${RED}❌ Please don't run as root${NC}"
   exit 1
fi

echo -e "${YELLOW}📦 Updating package list...${NC}"
sudo apt update -qq

echo -e "${YELLOW}🐍 Installing Python and pip...${NC}"
sudo apt install -y python3 python3-pip

echo -e "${YELLOW}📚 Installing Python libraries...${NC}"
pip3 install --user requests dnspython urllib3

echo -e "${YELLOW}🛠️  Installing Go (for security tools)...${NC}"
if ! command -v go &> /dev/null; then
    wget -q https://go.dev/dl/go1.21.5.linux-amd64.tar.gz
    sudo tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz
    rm go1.21.5.linux-amd64.tar.gz
    echo 'export PATH=$PATH:/usr/local/go/bin:~/go/bin' >> ~/.bashrc
    export PATH=$PATH:/usr/local/go/bin:~/go/bin
    echo -e "${GREEN}✅ Go installed${NC}"
else
    echo -e "${GREEN}✅ Go already installed${NC}"
fi

echo -e "${YELLOW}🔧 Installing subdomain enumeration tools...${NC}"

# subfinder
echo "  Installing subfinder..."
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null || echo "  ⚠️ May need manual install"

# assetfinder
echo "  Installing assetfinder..."
go install github.com/tomnomnom/assetfinder@latest 2>/dev/null || echo "  ⚠️ May need manual install"

# amass
echo "  Installing amass..."
sudo apt install -y amass 2>/dev/null || echo "  ⚠️ May need manual install"

echo -e "${YELLOW}🔍 Verifying installations...${NC}"
tools=("subfinder" "assetfinder" "amass")
for tool in "${tools[@]}"; do
    if command -v $tool &> /dev/null; then
        echo -e "  ${GREEN}✅ $tool${NC}"
    else
        echo -e "  ${RED}❌ $tool (not found)${NC}"
    fi
done

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                    ✅ INSTALLATION COMPLETE                   ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "🎯 To use TakeoverHunter:"
echo ""
echo "  1. Restart terminal or run: source ~/.bashrc"
echo ""
echo "  2. Run the tool:"
echo "     python3 takeoverhunter.py example.com"
echo ""
echo "  3. Or make it executable:"
echo "     chmod +x takeoverhunter.py"
echo "     ./takeoverhunter.py example.com"
echo ""
echo "🧪 Test with: scanme.nmap.org (should find nothing, good for testing)"
echo "🔥 Real targets: bug bounty programs with wildcard scopes"
echo ""
echo "💡 Tip: Set GITHUB_TOKEN env var for better GitHub validation:"
echo "     export GITHUB_TOKEN=your_token_here"
echo ""
