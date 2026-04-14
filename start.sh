#!/bin/bash
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}=====================================${NC}"
echo -e "${GREEN}      ZENITH-SENTRY LAUNCHER       ${NC}"
echo -e "${GREEN}=====================================${NC}"


if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Error: python3 is not installed or not in PATH.${NC}"
    exit 1
fi

VENV_DIR=".venv"


if [ ! -d "$VENV_DIR" ]; then
    echo -e "${YELLOW}Virtual environment ($VENV_DIR) not found.${NC}"
    read -p "Do you want to create and setup the environment now? [Y/n] " response
    response=${response,,} 
    if [[ "$response" =~ ^(yes|y|)$ ]]; then
        echo "Creating virtual environment..."
        
        python3 -m venv --without-pip --system-site-packages $VENV_DIR
        
        if [ $? -ne 0 ]; then
             echo -e "${RED}Failed to create virtual environment.${NC}"
             exit 1
        fi

        echo "Installing PyYAML dependency..."
        mkdir -p $VENV_DIR/lib/python3.13/site-packages
        curl -sSL https://files.pythonhosted.org/packages/source/P/PyYAML/PyYAML-6.0.1.tar.gz -o pyyaml.tar.gz
        tar -xzf pyyaml.tar.gz
        mv PyYAML-6.0.1/lib/yaml $VENV_DIR/lib/python3.13/site-packages/
        rm -rf pyyaml.tar.gz PyYAML-6.0.1

        echo -e "${GREEN}Environment setup complete!${NC}"
    else
        echo "Environment setup aborted. Cannot start."
        exit 1
    fi
else
    echo -e "${GREEN}Virtual environment found.${NC}"
fi

source $VENV_DIR/bin/activate

if [ ! -f "gui.py" ]; then
    echo -e "${RED}Error: gui.py not found.${NC}"
    exit 1
fi


echo "Starting Interface..."
python3 gui.py


echo -e "${YELLOW}Cleaning up virtual environment...${NC}"
deactivate 2>/dev/null || true
rm -rf $VENV_DIR
echo -e "${GREEN}Cleanup complete. Goodbye!${NC}"
