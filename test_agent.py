from aegis.engine import ToolFirewall

firewall = ToolFirewall()

@firewall.guard(tool_name="read_file", agent_id="enterprise-agent")
def access_file(filepath: str):
    return f"Read content from: {filepath}"

if __name__ == "__main__":
    # Test safe path
    try:
        safe_res = access_file("/var/app/data.txt")
        print(f"Success: {safe_res}")
    except Exception as e:
        print(f"Error: {e}")

    # Test enterprise threat path traversal
    try:
        result = access_file("../../etc/passwd")
        print(result)
    except Exception as e:
        print(f"Enterprise Firewall successfully blocked the threat: {e}")