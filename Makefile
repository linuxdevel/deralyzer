# deralyzer - ASN.1 DER/PEM analyzer
# Copyright (C) 2025 Arne Brune Olsen
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -Werror -O2
LDFLAGS = -lssl -lcrypto

SRC_DIR = src
BUILD_DIR = build
TARGET = deralyzer

SRCS = $(wildcard $(SRC_DIR)/*.cpp)
OBJS = $(patsubst $(SRC_DIR)/%.cpp, $(BUILD_DIR)/%.o, $(SRCS))

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(OBJS) -o $@ $(LDFLAGS)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.cpp | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

test: $(TARGET)
	@echo "Generating test keys..."
	@openssl genrsa -out test_key.pem 2048 2>/dev/null
	@openssl rsa -in test_key.pem -outform DER -out test_key.der 2>/dev/null
	@echo "Running tests..."
	@./$(TARGET) -in test_key.der -inform der -outform tree > /dev/null && echo "DER Input Test: PASSED" || echo "DER Input Test: FAILED"
	@./$(TARGET) -in test_key.pem -inform pem -outform tree > /dev/null && echo "PEM Input Test: PASSED" || echo "PEM Input Test: FAILED"
	@rm -f test_key.pem test_key.der
	@echo "Tests completed."

install: $(TARGET)
	@echo "Enter installation prefix (default: /usr/local): "; \
	read prefix; \
	prefix=$${prefix:-/usr/local}; \
	echo "Installing to $${prefix}/bin ..."; \
	mkdir -p "$${prefix}/bin"; \
	cp $(TARGET) "$${prefix}/bin/"; \
	cp deralyzer.cfg "$${prefix}/bin/"; \
	chmod 755 "$${prefix}/bin/$(TARGET)"; \
	chmod 644 "$${prefix}/bin/deralyzer.cfg"; \
	echo "Installation complete."

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

clean:
	rm -rf $(BUILD_DIR) $(TARGET)
