import requests
import csv

# put in the cluster address you have access to from where you run this script
VAULT_ADDR = "https://vault-cluster-address:8200"

# high access vault token that can walk the namespaces and list/read roles
VAULT_TOKEN = ""
HEADERS = {"X-Vault-Token": VAULT_TOKEN}

# I tested this script on hcp vault so this top level admin ns was needed
# I believe with your cluster this should be:
# TOP_LEVEL_NS = ""
TOP_LEVEL_NS = "admin/"

def list_namespaces(namespace=""):
    url = f"{VAULT_ADDR}/v1/{namespace}sys/namespaces"
    response = requests.request("LIST", url, headers=HEADERS)
    if response.status_code == 200:
        return response.json().get("data", {}).get("keys", [])
    return []

def list_roles(namespace, method):
    url = f"{VAULT_ADDR}/v1/{namespace}auth/{method}/role"
    response = requests.request("LIST", url, headers=HEADERS)
    if response.status_code == 200:
        return response.json().get("data", {}).get("keys", [])
    return []

def read_role(namespace, method, role):
    """
    Read details of a specific role in a namespace and auth method.
    """
    url = f"{VAULT_ADDR}/v1/{namespace}auth/{method}/role/{role}"
    response = requests.get(url, headers=HEADERS)
    if response.status_code == 200:
        role_data = response.json().get("data", {})
        return role_data.get("bound_claims", {})
    else:
        print(f"Error reading role {role} in {namespace}: {response.text}")
        return None

# Discover namespaces recursively
def discover_namespaces(base_namespace):
    namespaces = list_namespaces(base_namespace)
    all_namespaces = [base_namespace]
    for ns in namespaces:
        full_ns = f"{base_namespace}{ns}" if base_namespace else ns
        all_namespaces += discover_namespaces(full_ns)
    return all_namespaces

# Main Script
def main():
    # Prepare CSV file
    csv_file = "vault_roles.csv"
    namespace_ids = set()

    with open(csv_file, mode="w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["Namespace", "Role Name", "Bound Claims", "Auth Method"])

        # Discover all namespaces
        all_namespaces = discover_namespaces(TOP_LEVEL_NS)
        
        print("Discovered namespaces:")
        for ns in all_namespaces:
            print(f"- {ns}")
            
            # Check auth methods in the namespace
            for method in ["jwt"]:  # Add other auth methods as needed
                roles = list_roles(ns, method)
                if roles:
                    print(f"  Roles under auth/{method}:")
                    for role in roles:
                        print(f"    - {role}")
                        bound_claims = read_role(ns, method, role)
                        if bound_claims:
                            print(f"      Bound claims for role {role}: {bound_claims}")
                            # Extract namespace IDs if present
                            if "namespace_id" in bound_claims:
                                namespace_ids.update(bound_claims["namespace_id"])
                            # Write to CSV
                            writer.writerow([ns, role, bound_claims, method])
    # Print unique namespace IDs
    print("\nUnique Namespace IDs:")
    for namespace_id in sorted(namespace_ids):
        print(f"- {namespace_id}")
    print(f"\nTotal unique namespace IDs: {len(namespace_ids)}")

if __name__ == "__main__":
    main()