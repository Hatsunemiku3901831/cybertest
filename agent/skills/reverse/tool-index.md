# Tool Index

- Generated at: 2026-06-08 17:17:40 +0800
- Platform: macos (Darwin 24.6.0)
- Script: `skills/scripts/refresh-tool-index.sh`
- Note: This script detects tools only. It does not install tools.

| Tool | Skill | Purpose | Available | Path | Version | Install hint |
|---|---|---|-------|---|---|---|
| java | core-runtime | Java runtime for jadx/apktool/Burp/Ghidra | yes   | /opt/homebrew/Cellar/openjdk@17/17.0.18/libexec/openjdk.jdk/Contents/Home/bin/java | openjdk version "17.0.18" 2026-01-20 | brew: brew install openjdk |
| python3 | core-runtime | Python runtime for helper scripts and pipx tools | yes   | /Users/umisonoda/PycharmProjects/cybertest/.venv/bin/python3 | Python 3.12.0 | brew: brew install python; then pipx/venv |
| pipx | core-runtime | Isolated Python CLI installer | yes   | /opt/homebrew/bin/pipx | 1.13.0 | see PLATFORMS.md and docs/platforms/macos.md |
| node | core-runtime | Node.js runtime for MCP bridges | yes   | /opt/homebrew/bin/node | v26.0.0 | brew/nvm: brew install node; or nvm |
| npm | core-runtime | Node package manager | yes   | /opt/homebrew/bin/npm | 11.12.1 | see PLATFORMS.md and docs/platforms/macos.md |
| npx | core-runtime | Run npm MCP packages | yes   | /opt/homebrew/bin/npx | 11.12.1 | see PLATFORMS.md and docs/platforms/macos.md |
| jadx | apk-reverse | APK Java/Kotlin decompiler | yes   | /opt/homebrew/bin/jadx | 1.5.5 | brew: brew install jadx |
| apktool | apk-reverse | APK decode and rebuild | yes   | /opt/homebrew/bin/apktool | 3.0.2 | brew: brew install apktool |
| adb | apk-reverse | Android device bridge | yes   | /opt/homebrew/bin/adb | Android Debug Bridge version 1.0.41 | brew: brew install android-platform-tools |
| frida | reverse-engineering | Dynamic instrumentation CLI | yes   | /Users/umisonoda/.local/bin/frida | 17.10.1 | pipx: pipx install frida-tools |
| frida-ps | reverse-engineering | Frida process listing | yes   | /Users/umisonoda/.local/bin/frida-ps | 17.10.1 | see PLATFORMS.md and docs/platforms/macos.md |
| r2 | radare2 | radare2 CLI analysis | yes   | /opt/homebrew/bin/r2 | radare2 6.1.6 +0 abi:107 @ darwin-arm_64 | brew: brew install radare2 |
| rabin2 | radare2 | Binary metadata extraction | yes   | /opt/homebrew/bin/rabin2 | rabin2 6.1.6 +0 abi:107 @ darwin-arm_64 | see PLATFORMS.md and docs/platforms/macos.md |
| ghidra | reverse-engineering | Ghidra reverse-engineering suite | no    | — | — | brew: brew install ghidra or brew install --cask ghidra |
| idapro | ida-reverse | IDA Pro commercial reverse-engineering suite | no    | — | — | see PLATFORMS.md and docs/platforms/macos.md |
| burpsuite | burp-mcp | BurpSuite desktop application | no    | — | — | brew cask/manual: brew install --cask burp-suite |
| graphviz | diagram-generator | Graphviz diagram rendering | yes   | /opt/homebrew/bin/dot | dot - graphviz version 15.0.0 (20260523.1842) | see PLATFORMS.md and docs/platforms/macos.md |
| plantuml | diagram-generator | PlantUML diagram rendering | yes   | /opt/homebrew/bin/plantuml | PlantUML version 1.2026.5 / e0f0ce5 [2026-05-27 17:39:27 UTC] | see PLATFORMS.md and docs/platforms/macos.md |
| nmap | pentest-tools | Network scanner | yes   | /opt/homebrew/bin/nmap | Nmap version 7.99 ( https://nmap.org ) | see PLATFORMS.md and docs/platforms/macos.md |
| sqlmap | pentest-tools | SQL injection testing tool | yes   | /opt/homebrew/bin/sqlmap | 1.10.6#stable | see PLATFORMS.md and docs/platforms/macos.md |
| ffuf | pentest-tools | Web fuzzer | yes   | /opt/homebrew/bin/ffuf | ffuf version: 2.1.0-dev | see PLATFORMS.md and docs/platforms/macos.md |
| hashcat | pentest-tools | Password recovery | yes   | /opt/homebrew/bin/hashcat | v7.1.2 | see PLATFORMS.md and docs/platforms/macos.md |
| nuclei | pentest-tools | Template-based vulnerability scanner | yes   | /opt/homebrew/bin/nuclei | [[34mINF[0m] Nuclei Engine Version: v3.8.0 | brew: brew install nuclei |
| binwalk | firmware-pentest | Firmware extraction and analysis | yes   | /opt/homebrew/bin/binwalk | binwalk 3.1.0 | see PLATFORMS.md and docs/platforms/macos.md |
| seclists | pentest-tools | Security wordlists | no    | — | — | git clone https://github.com/danielmiessler/SecLists ~/tools/SecLists |
| jshookmcp | js-reverse | JS/CDP/Hook MCP runtime via npx | yes   | /opt/homebrew/bin/npx | 11.12.1 | npx: npx -y @jshookmcp/jshook@latest |
| anything-analyzer | browser-automation | Browser/HTTP analyzer MCP project | yes   | — | — | git clone + corepack enable + pnpm install + pnpm dev |
| burp-mcp-full | burp-mcp | Local Burp MCP extension and stdio bridge | no    | — | — | see PLATFORMS.md and docs/platforms/macos.md |

---

## Next steps

- Read `docs/platforms/macos.md` for Homebrew and app-bundle setup.
- Register MCP servers in your Agent client; tool availability does not imply MCP registration.
