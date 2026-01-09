/*
 * deralyzer - ASN.1 DER/PEM analyzer
 * Copyright (C) 2025 Arne Brune Olsen
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstring>
#include <iomanip>
#include <algorithm>
#include <map>
#include <sstream>
#include <unistd.h>
#include <limits.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/objects.h>

std::map<std::string, std::string> oidConfigMap;

enum InputFormat {
    FORMAT_DER,
    FORMAT_PEM,
    FORMAT_AUTO
};

enum OutputFormat {
    OUTPUT_TEXT,
    OUTPUT_HEX,
    OUTPUT_TREE
};

struct Config {
    std::string inputFile;
    InputFormat inputFormat = FORMAT_AUTO;
    OutputFormat outputFormat = OUTPUT_TREE;
    bool verbose = false;
    bool useColor = false;
    bool fullOutput = false;
};

// ANSI Color Codes
const char* C_RST = "\033[0m";
const char* C_RED = "\033[31m";
const char* C_GRN = "\033[32m";
const char* C_YEL = "\033[33m";
const char* C_BLU = "\033[34m";
const char* C_MAG = "\033[35m";
const char* C_CYN = "\033[36m";
const char* C_GRY = "\033[90m";

std::string colorize(const std::string& text, const char* colorCode, bool enabled) {
    if (!enabled) return text;
    return std::string(colorCode) + text + C_RST;
}

struct Issue {
    long offset;
    std::string message;
    bool isError;
};

struct AnalysisReport {
    std::vector<Issue> issues;
    bool hasIndefiniteLength = false;
    bool derCompliant = true;
};

void printUsage(const char* progName) {
    std::cerr << "Usage: " << progName << " -in <file> [-inform der|pem] [-outform text|hex|tree] [-v] [--color] [--full-output]" << std::endl;
    std::cerr << "       (All options support both single '-' and double '--' dashes)" << std::endl;
}

// Helper to convert PEM to DER
bool pemToDer(const std::vector<unsigned char>& pemData, std::vector<unsigned char>& derData) {
    BIO* bio = BIO_new_mem_buf(pemData.data(), static_cast<int>(pemData.size()));
    if (!bio) return false;

    char* name = nullptr;
    char* header = nullptr;
    unsigned char* data = nullptr;
    long len = 0;

    bool success = false;
    if (PEM_read_bio(bio, &name, &header, &data, &len)) {
        derData.assign(data, data + len);
        OPENSSL_free(name);
        OPENSSL_free(header);
        OPENSSL_free(data);
        success = true;
    }
    
    BIO_free(bio);
    return success;
}


void loadConfig(const char* argv0) {
    std::string exePath;
    char buf[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (len != -1) {
        buf[len] = '\0';
        exePath = buf;
    } else {
        // Fallback if /proc is not available, though unlikely on Linux
        exePath = argv0; 
    }

    size_t lastSlash = exePath.find_last_of('/');
    std::string configPath = (lastSlash != std::string::npos) 
                           ? exePath.substr(0, lastSlash + 1) + "deralyzer.cfg"
                           : "deralyzer.cfg";

    std::ifstream cfgFile(configPath);
    if (!cfgFile.is_open()) return;

    // Simple JSON parser (since we don't have nlohmann/json or similar heavy libs available guaranteed)
    // We expect the format: "OID": { "description": "Desc", "warning": true/false }
    // This is a very rough parser specifically for this structure.
    
    std::string content((std::istreambuf_iterator<char>(cfgFile)), std::istreambuf_iterator<char>());
    
    // Remove whitespace/newlines to simplify parsing
    // But keep spaces inside quotes!
    std::string cleanContent;
    bool inQuote = false;
    for (char c : content) {
        if (c == '"') inQuote = !inQuote;
        if (inQuote || (!isspace(c) && c != '\n' && c != '\r')) {
            cleanContent += c;
        }
    }
    
    size_t pos = 0;
    while (pos < cleanContent.length()) {
        // Find key (OID)
        size_t keyStart = cleanContent.find('"', pos);
        if (keyStart == std::string::npos) break;
        size_t keyEnd = cleanContent.find('"', keyStart + 1);
        if (keyEnd == std::string::npos) break;
        
        std::string oid = cleanContent.substr(keyStart + 1, keyEnd - keyStart - 1);
        
        // Find value object start
        size_t valStart = cleanContent.find('{', keyEnd);
        if (valStart == std::string::npos) break;
        
        // Find matching closing brace
        size_t valEnd = valStart;
        int braceCount = 0;
        bool inQ = false;
        for (size_t i = valStart; i < cleanContent.length(); i++) {
            if (cleanContent[i] == '"') inQ = !inQ;
            if (!inQ) {
                if (cleanContent[i] == '{') braceCount++;
                else if (cleanContent[i] == '}') {
                    braceCount--;
                    if (braceCount == 0) {
                        valEnd = i;
                        break;
                    }
                }
            }
        }
        
        std::string valObj = cleanContent.substr(valStart, valEnd - valStart + 1);
        
        // Extract Description
        std::string desc;
        size_t descKey = valObj.find("\"description\"");
        if (descKey != std::string::npos) {
            size_t colon = valObj.find(':', descKey);
            size_t qStart = valObj.find('"', colon);
            size_t qEnd = valObj.find('"', qStart + 1);
            if (qEnd != std::string::npos) {
                desc = valObj.substr(qStart + 1, qEnd - qStart - 1);
            }
        }
        
        // Extract Warning
        bool warn = false;
        if (valObj.find("\"warning\":true") != std::string::npos) {
            warn = true;
        }

        if (!desc.empty()) {
            if (warn) desc += " [WARNING]";
            oidConfigMap[oid] = desc;
        }
        
        pos = valEnd + 1;
    }
}

void printOID(ASN1_OBJECT* oid, bool useColor) {
    char buf[1024];
    int len = OBJ_obj2txt(buf, sizeof(buf), oid, 1); // 1 for numeric
    if (len > 0) {
        std::cout << " " << colorize(buf, C_GRN, useColor);
        
        std::string oidStr(buf);
        std::string desc;
        if (oidConfigMap.count(oidStr)) {
            desc = oidConfigMap[oidStr];
        } else {
            // Try to get the friendly name from OpenSSL
            int nid = OBJ_obj2nid(oid);
            if (nid != NID_undef) {
                const char* name = OBJ_nid2ln(nid);
                if (name) desc = name;
            }
        }

        if (!desc.empty()) {
            if (desc.find("[WARNING]") != std::string::npos) {
                std::cout << " (" << colorize(desc, C_RED, useColor) << ")";
            } else {
                std::cout << " (" << colorize(desc, C_CYN, useColor) << ")";
            }
        }
    }
}

void printKeyUsage(const unsigned char* data, long len, bool useColor) {
    if (len < 2) return; // Need at least unused bits byte + 1 byte of flags
    
    // Skip unused bits byte for now to check flags
    unsigned char flags = data[1];
    std::vector<std::string> usages;
    
    if (flags & 0x80) usages.push_back("digitalSignature");
    if (flags & 0x40) usages.push_back("nonRepudiation");
    if (flags & 0x20) usages.push_back("keyEncipherment");
    if (flags & 0x10) usages.push_back("dataEncipherment");
    if (flags & 0x08) usages.push_back("keyAgreement");
    if (flags & 0x04) usages.push_back("keyCertSign");
    if (flags & 0x02) usages.push_back("cRLSign");
    if (flags & 0x01) usages.push_back("encipherOnly");
    if (len > 2 && (data[2] & 0x80)) usages.push_back("decipherOnly");

    if (!usages.empty()) {
        std::cout << " " << colorize("(", C_CYN, useColor);
        for (size_t i = 0; i < usages.size(); ++i) {
            std::cout << colorize(usages[i], C_CYN, useColor);
            if (i < usages.size() - 1) std::cout << ", ";
        }
        std::cout << colorize(")", C_CYN, useColor);
    }
}

void printHexBody(const unsigned char* data, long len, int indent, bool useColor, bool fullOutput) {
    const int bytesPerLine = 16;
    long printLen = fullOutput ? len : std::min(len, 32L); 

    for (long i = 0; i < printLen; i += bytesPerLine) {
        std::cout << std::string(indent + 7, ' '); 
        
        long lineLen = std::min((long)bytesPerLine, printLen - i);
        
        // Hex part
        for (long j = 0; j < bytesPerLine; ++j) {
            if (j < lineLen) {
                std::cout << colorize("", C_GRY, useColor) 
                          << std::hex << std::setw(2) << std::setfill('0') << (int)data[i + j] << " "
                          << (useColor ? C_RST : "");
            } else {
                std::cout << "   "; // Padding
            }
        }
        
        // ASCII part
        std::cout << " |";
        for (long j = 0; j < lineLen; ++j) {
            unsigned char c = data[i + j];
            char display = (c >= 32 && c <= 126) ? (char)c : '.';
            std::cout << colorize(std::string(1, display), C_CYN, useColor);
        }
        std::cout << "|" << std::dec << std::endl;
    }
    
    if (!fullOutput && len > printLen) {
        std::cout << std::string(indent + 7, ' ') << colorize("... [truncated]", C_GRY, useColor) << std::endl;
    }
}

bool looksLikeASN1(const unsigned char* data, long len) {
    if (len < 2) return false;
    const unsigned char* p = data;
    long length = len;
    long objLen;
    int tag, xclass;
    
    // Check first object specifically for our heuristic
    const unsigned char* firstP = p;
    int ret = ASN1_get_object(&firstP, &objLen, &tag, &xclass, length);
    if (ret & 0x80) return false;
    
    // Heuristic: We only want to recurse if the content LOOKS like a container.
    // 1. Must be Universal class for standard types
    // 2. Must be SEQUENCE, SET, OCTET STRING, or BIT STRING.
    if (xclass == V_ASN1_UNIVERSAL) {
        if (tag != V_ASN1_SEQUENCE && tag != V_ASN1_SET && 
            tag != V_ASN1_BIT_STRING && tag != V_ASN1_OCTET_STRING) {
            return false;
        }
    } else if (xclass == V_ASN1_CONTEXT_SPECIFIC) {
         // Allow Context Specific Constructed tags (often used in Explicit tagging)
         if (!(ret & V_ASN1_CONSTRUCTED)) return false;
    } else {
        // Private or Application tags - treat as blob unless we know better
        return false;
    }

    // Now validate the WHOLE buffer structure ensures it parses cleanly
    p = data;
    length = len;
    while (length > 0) {
        const unsigned char* objStart = p;
        ret = ASN1_get_object(&p, &objLen, &tag, &xclass, length);
        
        if (ret & 0x80) return false; // Parse error

        long headerLen = p - objStart;
        if (headerLen + objLen > length) return false; // Length overflow

        // Move to next object
        p += objLen;
        length -= (headerLen + objLen);
    }

    return true;
}

std::string identifyArtifact(const std::vector<unsigned char>& data) {
    const unsigned char* p = data.data();
    if (d2i_X509(NULL, &p, data.size())) return "X.509 Certificate";
    p = data.data();
    if (d2i_X509_CRL(NULL, &p, data.size())) return "X.509 CRL";
    p = data.data();
    if (d2i_X509_REQ(NULL, &p, data.size())) return "X.509 CSR";
    return "Unknown / Generic ASN.1 Structure";
}

void printSummary(const AnalysisReport& report, const std::string& artifactType, bool useColor) {
    std::cout << "\n" << colorize("----- Analysis Summary -----", C_BLU, useColor) << std::endl;
    std::cout << "Detected Type: " << colorize(artifactType, C_MAG, useColor) << std::endl;
    
    std::string status = report.derCompliant ? "PASS" : "FAIL";
    const char* statusColor = report.derCompliant ? C_GRN : C_RED;
    std::cout << "DER Compliance: " << colorize(status, statusColor, useColor) << std::endl;
    
    if (report.hasIndefiniteLength) {
        std::cout << "  - " << colorize("Indefinite lengths found (Not allowed in DER)", C_RED, useColor) << std::endl;
    }
    
    std::cout << "Issues found: " << report.issues.size() << std::endl;
    for (const auto& issue : report.issues) {
        const char* lvlColor = issue.isError ? C_RED : C_YEL;
        std::cout << "  [" << colorize(issue.isError ? "ERROR" : "WARN", lvlColor, useColor) << "] Offset " << issue.offset 
                  << ": " << issue.message << std::endl;
    }
}

void checkInteger(const unsigned char* data, long len, long offset, AnalysisReport& report) {
    if (len > 1) {
        if (data[0] == 0x00 && (data[1] & 0x80) == 0) {
            report.issues.push_back({offset, "Integer not minimally encoded (leading zero)", false});
            report.derCompliant = false;
        }
        if (data[0] == 0xFF && (data[1] & 0x80) != 0) {
             report.issues.push_back({offset, "Integer not minimally encoded (leading 0xFF)", false});
             report.derCompliant = false;
        }
    }
}

void checkBitString(const unsigned char* data, long len, long offset, AnalysisReport& report) {
    if (len < 1) {
        report.issues.push_back({offset, "Bit String empty (missing unused bits count)", true});
        return;
    }
    int unused = data[0];
    if (unused > 7) {
        report.issues.push_back({offset, "Invalid unused bits count in Bit String (> 7)", true});
        return;
    }
    if (len > 1) {
        unsigned char lastByte = data[len-1];
        if (lastByte & ((1 << unused) - 1)) {
            report.issues.push_back({offset, "Unused bits in Bit String are not zero", false});
            report.derCompliant = false;
        }
    }
}

void checkBoolean(const unsigned char* data, long len, long offset, AnalysisReport& report) {
    if (len != 1) {
        report.issues.push_back({offset, "Boolean length must be 1", true});
        return;
    }
    if (data[0] != 0x00 && data[0] != 0xFF) {
        report.issues.push_back({offset, "Boolean value must be 0x00 or 0xFF for DER", false});
        report.derCompliant = false;
    }
}

struct AnalysisContext {
    AnalysisReport& report;
    bool useColor;
    bool fullOutput;
    int indent;
    long offsetBase;
    std::string lastOID; // Track the last seen OID to identify context (like KeyUsage)
};

void parseASN1Custom(const unsigned char* data, long len, AnalysisContext ctx) {
    const unsigned char* p = data;
    long length = len;
    int tag, xclass;
    
    while (length > 0) {
        long objLen;
        long headerLen;
        const unsigned char* objStart = p;
        int ret = ASN1_get_object(&p, &objLen, &tag, &xclass, length);
        
        // p now points to content
        // ASN1_get_object returns 0x80 on error
        if (ret & 0x80) {
            std::cerr << "Error decoding ASN.1 object" << std::endl;
            ctx.report.issues.push_back({ctx.offsetBase + (objStart - data), "Error decoding ASN.1 object", true});
            return;
        }
        
        if (ret & 0x01) {
            // Indefinite length
            ctx.report.hasIndefiniteLength = true;
            ctx.report.derCompliant = false;
        }

        headerLen = p - objStart;
        long currentOffset = ctx.offsetBase + (objStart - data);

        // Print header
        std::cout << std::setw(3) << std::right << currentOffset << " " 
                  << std::setw(3) << std::right << objLen << ": " 
                  << std::string(ctx.indent, ' ');

        if (xclass == V_ASN1_UNIVERSAL) {
            const char* tagName = ASN1_tag2str(tag);
            std::string tagStr = tagName ? tagName : ("Tag" + std::to_string(tag));
            std::cout << colorize(tagStr, C_BLU, ctx.useColor);
        } else if (xclass == V_ASN1_CONTEXT_SPECIFIC) {
            std::string label = "[" + std::to_string(tag) + "]";
            if (ret & V_ASN1_CONSTRUCTED) {
                label += " (Constructed)";
            }
            std::cout << colorize(label, C_YEL, ctx.useColor);
        } else if (xclass == V_ASN1_APPLICATION) {
            std::cout << colorize("Application [" + std::to_string(tag) + "]", C_YEL, ctx.useColor);
        } else {
            std::cout << colorize("Private [" + std::to_string(tag) + "]", C_YEL, ctx.useColor);
        }
        
        if (ret & 0x01) std::cout << colorize(" (Indefinite length)", C_RED, ctx.useColor);

        bool doHexDump = false;

        // Print content and Checks
        if (xclass == V_ASN1_UNIVERSAL) {
            if (tag == V_ASN1_OBJECT) {
                 ASN1_OBJECT* oid = d2i_ASN1_OBJECT(NULL, &objStart, headerLen + objLen);
                 if (oid) {
                     printOID(oid, ctx.useColor);
                     
                     char buf[1024];
                     if (OBJ_obj2txt(buf, sizeof(buf), oid, 1) > 0) {
                        ctx.lastOID = std::string(buf);
                     }
                     
                     ASN1_OBJECT_free(oid);
                     objStart = p - headerLen; 
                 }
            } else if (tag == V_ASN1_INTEGER) {
                checkInteger(p, objLen, currentOffset, ctx.report);
                // Short integers inline, long ones hexdump
                if (objLen <= 8) {
                     std::cout << " ";
                     for(int i=0; i<objLen; i++) 
                         std::cout << colorize("", C_GRY, ctx.useColor)
                                   << std::hex << std::setw(2) << std::setfill('0') << (int)p[i] << std::dec
                                   << (ctx.useColor ? C_RST : "");
                } else {
                    doHexDump = true;
                }
            } else if (tag == V_ASN1_BOOLEAN) {
                checkBoolean(p, objLen, currentOffset, ctx.report);
                if (objLen > 0) {
                     std::cout << " " << colorize((p[0] ? "TRUE" : "FALSE"), C_MAG, ctx.useColor);
                }
            } else if (tag == V_ASN1_BIT_STRING) {
                // In DER, BIT STRINGs must be primitive.
                if (!(ret & V_ASN1_CONSTRUCTED)) {
                    checkBitString(p, objLen, currentOffset, ctx.report);
                    
                    // Check if this is a KeyUsage extension based on last seen OID
                    // 2.5.29.15 is id-ce-keyUsage
                    if (ctx.lastOID == "2.5.29.15") {
                        printKeyUsage(p, objLen, ctx.useColor);
                    }

                    // BIT STRING has 1 unused bits byte at the start. 
                    // Content starts at p+1, length is objLen-1
                    if (objLen > 1 && p[0] == 0) { // Only try parsing if unused bits are 0 (byte aligned)
                         if (looksLikeASN1(p + 1, objLen - 1)) {
                             std::cout << colorize(" [Encapsulated Content] {", C_MAG, ctx.useColor) << std::endl;
                             AnalysisContext nextCtx = ctx;
                             nextCtx.indent += 2;
                             nextCtx.offsetBase = currentOffset + headerLen + 1; // +1 for unused bits byte
                             parseASN1Custom(p + 1, objLen - 1, nextCtx);
                             std::cout << std::string(7 + ctx.indent, ' ') << " : " << std::string(ctx.indent, ' ') << "}";
                         } else {
                             doHexDump = true;
                         }
                    } else {
                        doHexDump = true;
                    }
                }
            } else if (tag == V_ASN1_PRINTABLESTRING || tag == V_ASN1_UTF8STRING || 
                       tag == V_ASN1_IA5STRING || tag == V_ASN1_T61STRING || 
                       tag == V_ASN1_VISIBLESTRING || tag == V_ASN1_NUMERICSTRING) {
                std::cout << " '" << colorize(std::string((const char*)p, objLen), C_CYN, ctx.useColor) << "'";
            } else if (tag == V_ASN1_OCTET_STRING) {
                 if (!(ret & V_ASN1_CONSTRUCTED)) {
                     // Check for nested ASN.1
                     // Pass the OID context down if we are encapsulating
                     if (looksLikeASN1(p, objLen)) {
                         std::cout << colorize(" [Encapsulated Content] {", C_MAG, ctx.useColor) << std::endl;
                         AnalysisContext nextCtx = ctx;
                         nextCtx.indent += 2;
                         nextCtx.offsetBase = currentOffset + headerLen;
                         // Preserve the lastOID when diving in, so if we just saw ExtKeyUsage OID,
                         // the inner sequence knows about it.
                         parseASN1Custom(p, objLen, nextCtx);
                         std::cout << std::string(7 + ctx.indent, ' ') << " : " << std::string(ctx.indent, ' ') << "}";
                     } else {
                         doHexDump = true;
                     }
                 }
            }
        } else {
             // For non-Universal types (Context Specific, etc.), if it's primitive, we show the hex body.
             if (!(ret & V_ASN1_CONSTRUCTED)) {
                 doHexDump = true;
             }
        }

        if (ret & V_ASN1_CONSTRUCTED) {
            std::cout << " {" << std::endl;
            AnalysisContext nextCtx = ctx;
            nextCtx.indent += 2;
            nextCtx.offsetBase = currentOffset + headerLen;
            // Clear lastOID when entering a new generic container to avoid false associations,
            // UNLESS it is a sequence immediately following an OID in a higher context (common in X.509 extensions).
            // For X.509 extensions, the sequence is: SEQUENCE { OID, BOOLEAN opt, OCTET STRING }
            // So when we parse the OCTET STRING, we want to know the OID.
            // But if we are just traversing a generic sequence, maybe we should keep it? 
            // Actually, for X.509, the structure is linear:
            // Extensions ::= SEQUENCE SIZE (1..MAX) OF Extension
            // Extension ::= SEQUENCE { extnID OBJECT IDENTIFIER, critical BOOLEAN DEFAULT FALSE, extnValue OCTET STRING }
            // So the OID is seen, then the value follows.
            
            // However, ExtKeyUsage (2.5.29.37) is: SEQUENCE OF KeyPurposeId.
            // So if we are in a sequence and the *parent* or *previous sibling* was ExtKeyUsage, we might want to know.
            // But parseASN1Custom iterates siblings. `ctx` is passed by value.
            // So `ctx.lastOID` will be whatever was seen *before* this function call, OR updated within the loop.
            // If we enter a constructed type, we pass `ctx` which contains the `lastOID` seen *so far* in this loop.
            // This is actually correct for "Encapsulated Content" of extensions.
            
            parseASN1Custom(p, objLen, nextCtx);
            
            std::cout << std::string(7 + ctx.indent, ' ') << " : " << std::string(ctx.indent, ' ') << "}" << std::endl;

        } else {
             std::cout << std::endl;
             if (doHexDump) {
                 printHexBody(p, objLen, ctx.indent, ctx.useColor, ctx.fullOutput);
             }
        }

        // Advance
        p += objLen; 
        length -= (headerLen + objLen);
    }
}

void printHex(const unsigned char* data, long len, int indent = 0) {
    for (long i = 0; i < len; i++) {
        if (i > 0 && i % 16 == 0) {
            std::cout << std::endl;
            if (indent > 0) std::cout << std::string(indent, ' ');
        }
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)data[i] << " ";
    }
    std::cout << std::dec << std::endl;
}

int main(int argc, char* argv[]) {
    loadConfig(argv[0]);
    Config config;

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if ((arg == "-in" || arg == "--in") && i + 1 < argc) {
            config.inputFile = argv[++i];
        } else if ((arg == "-inform" || arg == "--inform") && i + 1 < argc) {
            std::string format = argv[++i];
            if (format == "der") config.inputFormat = FORMAT_DER;
            else if (format == "pem") config.inputFormat = FORMAT_PEM;
        } else if ((arg == "-outform" || arg == "--outform") && i + 1 < argc) {
            std::string format = argv[++i];
            if (format == "text") config.outputFormat = OUTPUT_TEXT;
            else if (format == "hex") config.outputFormat = OUTPUT_HEX;
            else if (format == "tree") config.outputFormat = OUTPUT_TREE;
        } else if (arg == "-v" || arg == "--verbose") {
            config.verbose = true;
        } else if (arg == "--color" || arg == "-color") {
            config.useColor = true;
        } else if (arg == "--full-output" || arg == "-full-output") {
            config.fullOutput = true;
        } else {
            printUsage(argv[0]);
            return 1;
        }
    }

    if (config.inputFile.empty()) {
        printUsage(argv[0]);
        return 1;
    }

    std::ifstream file(config.inputFile, std::ios::binary | std::ios::ate);
    if (!file) {
        std::cerr << "Could not open file: " << config.inputFile << std::endl;
        return 1;
    }

    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<unsigned char> buffer(size);
    if (!file.read((char*)buffer.data(), size)) {
        std::cerr << "Failed to read file" << std::endl;
        return 1;
    }

    std::vector<unsigned char> derData;
    
    // Auto-detect or use specified format
    bool isPem = false;
    if (config.inputFormat == FORMAT_PEM) {
        isPem = true;
    } else if (config.inputFormat == FORMAT_AUTO) {
        // Simple heuristic: check for "-----BEGIN"
        std::string s((char*)buffer.data(), size > 100 ? 100 : size);
        if (s.find("-----BEGIN") != std::string::npos) {
            isPem = true;
        }
    }

    if (isPem) {
        if (!pemToDer(buffer, derData)) {
            std::cerr << "Failed to parse PEM data" << std::endl;
            return 1;
        }
    } else {
        derData = buffer;
    }

    if (config.outputFormat == OUTPUT_HEX) {
        printHex(derData.data(), derData.size());
    } else if (config.outputFormat == OUTPUT_TREE || config.outputFormat == OUTPUT_TEXT) {
        AnalysisReport report;
        AnalysisContext ctx{report, config.useColor, config.fullOutput, 0, 0, ""};
        parseASN1Custom(derData.data(), static_cast<long>(derData.size()), ctx);
        
        // Identify
        std::string artifactType = identifyArtifact(derData);
        printSummary(report, artifactType, config.useColor);
    }

    return 0;
}
