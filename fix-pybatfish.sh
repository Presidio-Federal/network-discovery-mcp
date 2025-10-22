#!/bin/bash

# This script is meant to be run inside the container to fix pybatfish installation issues

echo "Checking pybatfish installation..."

# Try to import pybatfish
python3 -c "import pybatfish" 2>/dev/null
if [ $? -eq 0 ]; then
    echo "pybatfish is already installed correctly."
else
    echo "pybatfish import failed. Attempting to fix..."
    
    # Install pybatfish directly
    pip install --upgrade pybatfish
    
    # Check again
    python3 -c "import pybatfish" 2>/dev/null
    if [ $? -eq 0 ]; then
        echo "pybatfish installation fixed successfully."
    else
        echo "Failed to fix pybatfish installation. Installing dependencies..."
        
        # Install dependencies
        pip install --upgrade pandas matplotlib networkx requests
        
        # Try one more time
        pip install --upgrade pybatfish
        
        # Final check
        python3 -c "import pybatfish" 2>/dev/null
        if [ $? -eq 0 ]; then
            echo "pybatfish installation fixed successfully after installing dependencies."
        else
            echo "Failed to fix pybatfish installation. Manual intervention required."
        fi
    fi
fi

# Check if we can import the specific modules needed
python3 -c "from pybatfish.client.commands import bf_init_snapshot, bf_set_network, bf_session; from pybatfish.question import bfq" 2>/dev/null
if [ $? -eq 0 ]; then
    echo "All required pybatfish modules are available."
else
    echo "Some required pybatfish modules are missing. This may indicate a version mismatch or incomplete installation."
fi

echo "Done."
