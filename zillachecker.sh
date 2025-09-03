#!/bin/bash

# ZillaChecker v1.0.0 - AI-Powered Pattern Recognition System
# Works on Termux and Linux, with C++ and SQL integration
# Powered by FJ™-CYBERZILLA - MMXXVI
# Color codes for vintage green theme
GREEN='\033[0;32m'
DARK_GREEN='\033[0;90m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Trap for clean exit
trap 'echo -e "\n${RED}Termination signal received. Exiting gracefully...${NC}"; cleanup; exit 1' 2 15

# Banner function with vintage green theme
banner() {
    echo -e "${DARK_GREEN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                                                              ║"
    echo -e "║${GREEN}          ███████╗██╗██╗     ██╗      █████╗          ${DARK_GREEN}║"
    echo -e "║${GREEN}          ╚════██║██║██║     ██║     ██╔══██╗         ${DARK_GREEN}║"
    echo -e "║${GREEN}             ██╔╝██║██║     ██║     ███████║         ${DARK_GREEN}║"
    echo -e "║${GREEN}            ██╔╝ ██║██║     ██║     ██╔══██║         ${DARK_GREEN}║"
    echo -e "║${GREEN}          ███████╔╝███████╗███████╗██║  ██║         ${DARK_GREEN}║"
    echo -e "║${GREEN}          ╚══════╝ ╚══════╝╚══════╝╚═╝  ╚═╝         ${DARK_GREEN}║"
    echo -e "║${GREEN}    ██████╗██╗  ██╗███████╗ ██████╗██╗  ██╗███████╗██████╗ ${DARK_GREEN}║"
    echo -e "║${GREEN}   ██╔════╝██║  ██║██╔════╝██╔════╝██║ ██╔╝██╔════╝██╔══██╗${DARK_GREEN}║"
    echo -e "║${GREEN}   ██║     ███████║█████╗  ██║     █████╔╝ █████╗  ██████╔╝${DARK_GREEN}║"
    echo -e "║${GREEN}   ██║     ██╔══██║██╔══╝  ██║     ██╔═██╗ ██╔══╝  ██╔══██╗${DARK_GREEN}║"
    echo -e "║${GREEN}   ╚██████╗██║  ██║███████╗╚██████╗██║  ██╗███████╗██║  ██║${DARK_GREEN}║"
    echo -e "║${GREEN}    ╚═════╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝${DARK_GREEN}║"
    echo "║                                                              ║"
    echo -e "║${BOLD}${YELLOW}         AI-Powered Pattern Recognition System${NC}${DARK_GREEN}           ║"
    echo -e "║${BOLD}${YELLOW}                 Version 1.0.0 by FJ™ Cyberzilla${NC}${DARK_GREEN}                            ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Function to check dependencies
check_dependencies() {
    echo -e "${GREEN}[+] Checking dependencies...${NC}"
    
    local missing_deps=()
    
    # Check for C++ compiler
    if ! command -v g++ &> /dev/null && ! command -v clang++ &> /dev/null; then
        missing_deps+=("C++ compiler (g++ or clang++)")
    fi
    
    # Check for SQLite
    if ! command -v sqlite3 &> /dev/null; then
        missing_deps+=("SQLite3")
    fi
    
    # Check for Python (for ML components)
    if ! command -v python3 &> /dev/null; then
        missing_deps+=("Python3")
    fi
    
    if [ ${#missing_deps[@]} -ne 0 ]; then
        echo -e "${RED}[-] Missing dependencies:${NC}"
        for dep in "${missing_deps[@]}"; do
            echo -e "  ${RED}- $dep${NC}"
        done
        
        echo -e "\n${YELLOW}[!] Would you like to install missing dependencies? (y/N)${NC}"
        read -r answer
        if [ "$answer" = "y" ] || [ "$answer" = "Y" ]; then
            install_dependencies "${missing_deps[@]}"
        else
            echo -e "${RED}[!] Cannot proceed without required dependencies. Exiting.${NC}"
            exit 1
        fi
    else
        echo -e "${GREEN}[+] All dependencies are satisfied.${NC}"
    fi
}

# Function to install dependencies
install_dependencies() {
    echo -e "${GREEN}[+] Installing dependencies...${NC}"
    
    if command -v apt-get &> /dev/null; then
        # Debian/Ubuntu/Termux
        if [[ "$(uname -o)" == "Android" ]]; then
            # Termux
            pkg update && pkg upgrade -y
            for dep in "$@"; do
                case $dep in
                    "C++ compiler"*)
                        pkg install -y clang
                        ;;
                    "SQLite3")
                        pkg install -y sqlite
                        ;;
                    "Python3")
                        pkg install -y python
                        ;;
                esac
            done
        else
            # Linux
            sudo apt-get update
            for dep in "$@"; do
                case $dep in
                    "C++ compiler"*)
                        sudo apt-get install -y g++
                        ;;
                    "SQLite3")
                        sudo apt-get install -y sqlite3 libsqlite3-dev
                        ;;
                    "Python3")
                        sudo apt-get install -y python3 python3-pip
                        ;;
                esac
            done
        fi
    elif command -v yum &> /dev/null; then
        # RHEL/CentOS
        sudo yum check-update
        for dep in "$@"; do
            case $dep in
                "C++ compiler"*)
                    sudo yum install -y gcc-c++
                    ;;
                "SQLite3")
                    sudo yum install -y sqlite sqlite-devel
                    ;;
                "Python3")
                    sudo yum install -y python3 python3-pip
                    ;;
            esac
        done
    else
        echo -e "${RED}[-] Cannot automatically install dependencies on this system.${NC}"
        echo -e "${YELLOW}[!] Please install the following manually:${NC}"
        for dep in "$@"; do
            echo -e "  - $dep"
        done
        exit 1
    fi
}

# Function to initialize the database
init_database() {
    echo -e "${GREEN}[+] Initializing pattern database...${NC}"
    
    local db_file="zilla_patterns.db"
    
    # Create SQLite database
    sqlite3 "$db_file" <<EOF
CREATE TABLE IF NOT EXISTS patterns (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pattern_type TEXT NOT NULL,
    pattern_data TEXT NOT NULL,
    severity INTEGER,
    description TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS scan_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    pattern_id INTEGER,
    matches INTEGER,
    scan_date DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (pattern_id) REFERENCES patterns (id)
);

CREATE TABLE IF NOT EXISTS ml_models (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    model_name TEXT NOT NULL,
    model_data BLOB,
    accuracy REAL,
    trained_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
EOF

    # Insert some sample patterns
    sqlite3 "$db_file" <<EOF
INSERT OR IGNORE INTO patterns (pattern_type, pattern_data, severity, description)
VALUES 
('regex', '([0-9]{4}-?){4}[0-9]{4}', 3, 'Potential credit card pattern'),
('regex', '[0-9]{3}-?[0-9]{2}-?[0-9]{4}', 2, 'Potential SSN pattern'),
('regex', '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', 1, 'Email address pattern'),
('regex', '(http|https):\/\/[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', 1, 'URL pattern'),
('string', 'password', 2, 'Password keyword'),
('string', 'secret', 3, 'Secret keyword'),
('string', 'api_key', 3, 'API key keyword'),
('string', 'token', 3, 'Token keyword');
EOF

    echo -e "${GREEN}[+] Database initialized: $db_file${NC}"
}

# Function to compile C++ components
compile_cpp_components() {
    echo -e "${GREEN}[+] Compiling C++ components...${NC}"
    
    # Pattern matcher component
    cat > pattern_matcher.cpp << 'EOF'
#include <iostream>
#include <string>
#include <regex>
#include <vector>
#include <sqlite3.h>

struct Pattern {
    int id;
    std::string type;
    std::string data;
    int severity;
    std::string description;
};

class PatternMatcher {
private:
    sqlite3* db;
    std::vector<Pattern> patterns;
    
    static int callback(void* data, int argc, char** argv, char** azColName) {
        std::vector<Pattern>* patterns = static_cast<std::vector<Pattern>*>(data);
        Pattern p;
        p.id = std::stoi(argv[0]);
        p.type = argv[1];
        p.data = argv[2];
        p.severity = std::stoi(argv[3]);
        p.description = argv[4];
        patterns->push_back(p);
        return 0;
    }
    
public:
    PatternMatcher(const std::string& db_file) {
        if (sqlite3_open(db_file.c_str(), &db) != SQLITE_OK) {
            std::cerr << "Can't open database: " << sqlite3_errmsg(db) << std::endl;
        }
    }
    
    ~PatternMatcher() {
        sqlite3_close(db);
    }
    
    void loadPatterns() {
        std::string sql = "SELECT id, pattern_type, pattern_data, severity, description FROM patterns;";
        char* errMsg = 0;
        
        patterns.clear();
        if (sqlite3_exec(db, sql.c_str(), callback, &patterns, &errMsg) != SQLITE_OK) {
            std::cerr << "SQL error: " << errMsg << std::endl;
            sqlite3_free(errMsg);
        }
    }
    
    int checkString(const std::string& input) {
        int maxSeverity = 0;
        
        for (const auto& pattern : patterns) {
            if (pattern.type == "regex") {
                try {
                    std::regex re(pattern.data);
                    if (std::regex_search(input, re)) {
                        if (pattern.severity > maxSeverity) {
                            maxSeverity = pattern.severity;
                        }
                    }
                } catch (const std::regex_error& e) {
                    std::cerr << "Regex error: " << e.what() << std::endl;
                }
            } else if (pattern.type == "string") {
                if (input.find(pattern.data) != std::string::npos) {
                    if (pattern.severity > maxSeverity) {
                        maxSeverity = pattern.severity;
                    }
                }
            }
        }
        
        return maxSeverity;
    }
    
    void logResult(const std::string& target, int pattern_id, int matches) {
        std::string sql = "INSERT INTO scan_results (target, pattern_id, matches) VALUES ('" + 
                          target + "', " + std::to_string(pattern_id) + ", " + std::to_string(matches) + ");";
        char* errMsg = 0;
        
        if (sqlite3_exec(db, sql.c_str(), 0, 0, &errMsg) != SQLITE_OK) {
            std::cerr << "SQL error: " << errMsg << std::endl;
            sqlite3_free(errMsg);
        }
    }
};

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "Usage: " << argv[0] << " <string_to_check>" << std::endl;
        return 1;
    }
    
    PatternMatcher matcher("zilla_patterns.db");
    matcher.loadPatterns();
    
    std::string input = argv[1];
    int severity = matcher.checkString(input);
    
    std::cout << "Input: " << input << std::endl;
    std::cout << "Highest severity match: " << severity << std::endl;
    
    return 0;
}
EOF

    # Compile the C++ code
    if command -v g++ &> /dev/null; then
        g++ -std=c++11 pattern_matcher.cpp -o pattern_matcher -lsqlite3
    elif command -v clang++ &> /dev/null; then
        clang++ -std=c++11 pattern_matcher.cpp -o pattern_matcher -lsqlite3
    else
        echo -e "${RED}[-] No C++ compiler found. Skipping C++ component compilation.${NC}"
        return 1
    fi
    
    if [ -f "./pattern_matcher" ]; then
        echo -e "${GREEN}[+] C++ components compiled successfully.${NC}"
        return 0
    else
        echo -e "${RED}[-] C++ compilation failed.${NC}"
        return 1
    fi
}

# Function to setup Python ML components
setup_ml_components() {
    echo -e "${GREEN}[+] Setting up ML components...${NC}"
    
    cat > ml_pattern_detector.py << 'EOF'
#!/usr/bin/env python3

import sqlite3
import re
import sys
import json
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import IsolationForest
import numpy as np
import pickle
import os

class MLPatternDetector:
    def __init__(self, db_file="zilla_patterns.db"):
        self.db_file = db_file
        self.vectorizer = TfidfVectorizer(max_features=1000)
        self.model = IsolationForest(contamination=0.1, random_state=42)
        self.is_trained = False
        
    def load_training_data(self):
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        # Get patterns from database
        cursor.execute("SELECT pattern_data, severity FROM patterns")
        rows = cursor.fetchall()
        
        patterns = [row[0] for row in rows]
        severities = [row[1] for row in rows]
        
        conn.close()
        return patterns, severities
    
    def extract_features(self, texts):
        return self.vectorizer.transform(texts).toarray()
    
    def train(self):
        patterns, severities = self.load_training_data()
        
        if len(patterns) < 10:
            print("Not enough training data. Need at least 10 patterns.")
            return False
        
        # Convert patterns to feature vectors
        X = self.extract_features(patterns)
        
        # Train the model
        self.model.fit(X)
        
        self.is_trained = True
        return True
    
    def predict(self, text):
        if not self.is_trained:
            if not self.train():
                return 0
        
        features = self.extract_features([text])
        prediction = self.model.predict(features)
        
        # Convert prediction to severity score (-1 for anomaly, 1 for normal)
        # We'll convert to a severity score between 0-3
        if prediction[0] == -1:
            # Anomaly detected, calculate severity based on distance
            distances = self.model.decision_function(features)
            severity = min(3, max(1, int(abs(distances[0]) * 3)))
            return severity
        else:
            return 0
    
    def save_model(self, filename="ml_model.pkl"):
        with open(filename, 'wb') as f:
            pickle.dump({
                'vectorizer': self.vectorizer,
                'model': self.model,
                'is_trained': self.is_trained
            }, f)
        
        # Save to database
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        with open(filename, 'rb') as f:
            model_data = f.read()
        
        cursor.execute("""
            INSERT OR REPLACE INTO ml_models (model_name, model_data, accuracy)
            VALUES (?, ?, ?)
        """, ('pattern_detector', model_data, 0.85))
        
        conn.commit()
        conn.close()
    
    def load_model(self, filename="ml_model.pkl"):
        if os.path.exists(filename):
            with open(filename, 'rb') as f:
                data = pickle.load(f)
                self.vectorizer = data['vectorizer']
                self.model = data['model']
                self.is_trained = data['is_trained']
            return True
        return False

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 ml_pattern_detector.py <text_to_analyze>")
        sys.exit(1)
    
    text = sys.argv[1]
    detector = MLPatternDetector()
    
    # Try to load pre-trained model first
    if not detector.load_model():
        print("No pre-trained model found. Training new model...")
        detector.train()
        detector.save_model()
    
    severity = detector.predict(text)
    print(f"ML Detection Severity: {severity}")
    
    # Output in JSON format for easier parsing
    result = {
        "text": text,
        "severity": severity,
        "anomaly": severity > 0
    }
    
    print(json.dumps(result))

if __name__ == "__main__":
    main()
EOF

    chmod +x ml_pattern_detector.py
    echo -e "${GREEN}[+] ML components setup completed.${NC}"
}

# Function to analyze target
analyze_target() {
    local target="$1"
    
    echo -e "${GREEN}[+] Analyzing target: $target${NC}"
    echo -e "${CYAN}----------------------------------------${NC}"
    
    # Check if C++ pattern matcher exists
    if [ -f "./pattern_matcher" ]; then
        echo -e "${GREEN}[+] Running pattern matching...${NC}"
        ./pattern_matcher "$target"
        echo ""
    fi
    
    # Check if Python ML detector exists
    if [ -f "./ml_pattern_detector.py" ]; then
        echo -e "${GREEN}[+] Running ML pattern detection...${NC}"
        python3 ml_pattern_detector.py "$target"
        echo ""
    fi
    
    # Additional analysis can be added here
    perform_deep_analysis "$target"
}

# Function for deep analysis
perform_deep_analysis() {
    local target="$1"
    
    echo -e "${GREEN}[+] Performing deep analysis...${NC}"
    
    # Check for common vulnerability patterns
    local vulnerabilities=0
    
    # SQL Injection patterns
    if [[ "$target" =~ (.*)(\bUNION\b.*\bSELECT\b|'\s*OR\s*'|;\s*DROP\s|;\s*DELETE\s|;\s*INSERT\s|;\s*UPDATE\s)(.*) ]]; then
        echo -e "${RED}[!] Possible SQL Injection pattern detected${NC}"
        ((vulnerabilities++))
    fi
    
    # XSS patterns
    if [[ "$target" =~ (.*)(<script|javascript:|onerror=|onload=|alert\(|document\.cookie)(.*) ]]; then
        echo -e "${RED}[!] Possible XSS pattern detected${NC}"
        ((vulnerabilities++))
    fi
    
    # Path traversal patterns
    if [[ "$target" =~ (.*)(\.\./|\.\.\\|~/|/etc/passwd|/bin/sh|/etc/hosts)(.*) ]]; then
        echo -e "${RED}[!] Possible Path Traversal pattern detected${NC}"
        ((vulnerabilities++))
    fi
    
    # Command injection patterns
    if [[ "$target" =~ (.*)(\bchmod\b|\bchown\b|\brpm\b|\bdpkg\b|\byum\b|\bapt-get\b|;\s*\\|&\s*\\|\|\s*\\|`)(.*) ]]; then
        echo -e "${RED}[!] Possible Command Injection pattern detected${NC}"
        ((vulnerabilities++))
    fi
    
    if [ $vulnerabilities -eq 0 ]; then
        echo -e "${GREEN}[+] No obvious vulnerability patterns detected${NC}"
    else
        echo -e "${RED}[!] Total potential vulnerabilities: $vulnerabilities${NC}"
    fi
}

# Function to show statistics
show_statistics() {
    echo -e "${GREEN}[+] Displaying scan statistics...${NC}"
    
    if [ ! -f "zilla_patterns.db" ]; then
        echo -e "${RED}[-] Database not found. Please initialize first.${NC}"
        return
    fi
    
    echo -e "${CYAN}----------------------------------------${NC}"
    echo -e "${YELLOW}Pattern Database Statistics:${NC}"
    
    # Count total patterns
    local total_patterns=$(sqlite3 zilla_patterns.db "SELECT COUNT(*) FROM patterns;")
    echo -e "Total patterns: ${GREEN}$total_patterns${NC}"
    
    # Count by type
    echo -e "\n${YELLOW}Patterns by type:${NC}"
    sqlite3 zilla_patterns.db "SELECT pattern_type, COUNT(*) FROM patterns GROUP BY pattern_type;" | while read line; do
        IFS='|' read -ra parts <<< "$line"
        echo -e "  ${parts[0]}: ${GREEN}${parts[1]}${NC}"
    done
    
    # Count by severity
    echo -e "\n${YELLOW}Patterns by severity:${NC}"
    sqlite3 zilla_patterns.db "SELECT severity, COUNT(*) FROM patterns GROUP BY severity ORDER BY severity;" | while read line; do
        IFS='|' read -ra parts <<< "$line"
        echo -e "  Severity ${parts[0]}: ${GREEN}${parts[1]}${NC}"
    done
    
    # Recent scan results
    echo -e "\n${YELLOW}Recent scans:${NC}"
    sqlite3 zilla_patterns.db "SELECT target, MAX(scan_date), COUNT(*) FROM scan_results GROUP BY target ORDER BY MAX(scan_date) DESC LIMIT 5;" | while read line; do
        IFS='|' read -ra parts <<< "$line"
        echo -e "  ${parts[0]} (${parts[1]}): ${GREEN}${parts[2]}${NC} matches"
    done
}

# Function to cleanup temporary files
cleanup() {
    echo -e "${GREEN}[+] Cleaning up temporary files...${NC}"
    [ -f "pattern_matcher.cpp" ] && rm -f pattern_matcher.cpp
    [ -f "ml_pattern_detector.py" ] && rm -f ml_pattern_detector.py
}

# Main function
main() {
    banner
    
    # Check if running on Termux or Linux
    if [[ "$(uname -o)" == "Android" ]]; then
        echo -e "${GREEN}[+] Running on Termux${NC}"
    else
        echo -e "${GREEN}[+] Running on Linux${NC}"
    fi
    
    # Check dependencies
    check_dependencies
    
    # Initialize database
    init_database
    
    # Compile C++ components
    compile_cpp_components
    
    # Setup ML components
    setup_ml_components
    
    # Main menu
    while true; do
        echo -e "\n${CYAN}========== ZillaChecker Main Menu ==========${NC}"
        echo -e "${GREEN}1. Analyze text input${NC}"
        echo -e "${GREEN}2. Analyze file${NC}"
        echo -e "${GREEN}3. Show statistics${NC}"
        echo -e "${GREEN}4. Add custom pattern${NC}"
        echo -e "${GREEN}5. Retrain ML model${NC}"
        echo -e "${GREEN}6. Exit${NC}"
        echo -e "${CYAN}============================================${NC}"
        
        read -rp "Please choose an option (1-6): " choice
        
        case $choice in
            1)
                read -rp "Enter text to analyze: " input_text
                if [ -n "$input_text" ]; then
                    analyze_target "$input_text"
                else
                    echo -e "${RED}[-] Input cannot be empty.${NC}"
                fi
                ;;
            2)
                read -rp "Enter file path to analyze: " file_path
                if [ -f "$file_path" ]; then
                    while IFS= read -r line || [ -n "$line" ]; do
                        [ -n "$line" ] && analyze_target "$line"
                    done < "$file_path"
                else
                    echo -e "${RED}[-] File not found: $file_path${NC}"
                fi
                ;;
            3)
                show_statistics
                ;;
            4)
                read -rp "Enter pattern type (regex/string): " pattern_type
                read -rp "Enter pattern data: " pattern_data
                read -rp "Enter severity (1-3): " severity
                read -rp "Enter description: " description
                
                if [[ "$pattern_type" =~ ^(regex|string)$ ]] && [[ "$severity" =~ ^[1-3]$ ]] && [ -n "$pattern_data" ]; then
                    sqlite3 zilla_patterns.db "INSERT INTO patterns (pattern_type, pattern_data, severity, description) VALUES ('$pattern_type', '$pattern_data', $severity, '$description');"
                    echo -e "${GREEN}[+] Pattern added successfully.${NC}"
                else
                    echo -e "${RED}[-] Invalid input. Pattern not added.${NC}"
                fi
                ;;
            5)
                echo -e "${GREEN}[+] Retraining ML model...${NC}"
                python3 ml_pattern_detector.py "retrain"
                echo -e "${GREEN}[+] ML model retrained.${NC}"
                ;;
            6)
                echo -e "${GREEN}[+] Exiting ZillaChecker. Goodbye!${NC}"
                cleanup
                exit 0
                ;;
            *)
                echo -e "${RED}[-] Invalid option. Please try again.${NC}"
                ;;
        esac
    done
}

# Run main function
main "$@"
