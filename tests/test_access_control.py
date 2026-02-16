"""
OWASP A01:2021 - Broken Access Control
Access Control Security Tests

Purpose: Validate that API properly restricts
access to resources based on user permissions.

Tests:
- IDOR (Insecure Direct Object References)
- Horizontal privilege escalation
- Vertical privilege escalation
- Parameter tampering
"""
import pytest
import requests
from config import (
    BASE_URL,
    REQUEST_TIMEOUT
)


class TestAccessControl:
    """
    Access Control test suite.
    
    Tests that API:
    1. Prevents IDOR attacks
    2. Enforces user boundaries
    3. Validates resource ownership
    4. Rejects parameter tampering
    """
    
    @pytest.fixture(autouse=True)
    def setup(self):
        """Setup for each test"""
        self.base_url = BASE_URL
        self.session = requests.Session()
        self.session.headers.update({
            "Content-Type": "application/json",
            "User-Agent": "Security-Test-Suite/1.0"
        })
    
    
    def test_idor_user_data_access(self):
        """
        Test: IDOR - Access other users' data
        
        OWASP: A01:2021 - Broken Access Control
        Risk: Critical
        
        IDOR = Insecure Direct Object Reference
        
        Scenario: User 1 tries to access User 2's data
        by simply changing the ID in the URL.
        
        Expected: Should require authorization
        Reality: JSONPlaceholder allows it (finding!)
        """
        # Get data for multiple users by changing ID
        user_ids = [1, 2, 3, 4, 5]
        accessible_users = []
        
        for user_id in user_ids:
            response = self.session.get(
                f"{self.base_url}/users/{user_id}",
                timeout=REQUEST_TIMEOUT
            )
            
            if response.status_code == 200:
                user_data = response.json()
                accessible_users.append({
                    "user_id": user_id,
                    "name": user_data.get("name"),
                    "email": user_data.get("email")
                })
        
        print(f"\n[IDOR Audit] Accessible user records:")
        for user in accessible_users:
            print(f"  User {user['user_id']}: "
                  f"{user['name']} ({user['email']})")
        
        # If all users accessible without auth = IDOR vulnerability
        if len(accessible_users) > 1:
            pytest.fail(
                f"IDOR VULNERABILITY: {len(accessible_users)} user "
                f"records accessible without authentication\n"
                f"Any user can access any other user's PII\n"
                f"Affected users: {[u['user_id'] for u in accessible_users]}\n"
                f"Data exposed: name, email, address, phone, company"
            )
        
        print(f"\n[PASS] IDOR: User data properly protected")
    
    
    def test_idor_posts_modification(self):
        """
        Test: IDOR - Modify other users' posts
        
        OWASP: A01:2021 - Broken Access Control
        Risk: Critical
        
        Scenario: Attacker modifies post belonging
        to another user by guessing/incrementing ID.
        
        Expected: Should verify post ownership
        Reality: Check if API validates ownership
        """
        # Try to modify posts belonging to different users
        issues = []
        
        for post_id in [1, 2, 3]:
            # First get the post to see who owns it
            get_response = self.session.get(
                f"{self.base_url}/posts/{post_id}",
                timeout=REQUEST_TIMEOUT
            )
            
            if get_response.status_code != 200:
                continue
                
            original_post = get_response.json()
            original_owner = original_post.get("userId")
            
            # Try to modify it as a different user
            attacker_user_id = 999  # Non-existent user
            
            put_response = self.session.put(
                f"{self.base_url}/posts/{post_id}",
                json={
                    "id": post_id,
                    "title": "HACKED BY ATTACKER",
                    "body": "This post was modified",
                    "userId": attacker_user_id
                },
                timeout=REQUEST_TIMEOUT
            )
            
            # Should return 403 (Forbidden) not 200
            if put_response.status_code == 200:
                issues.append({
                    "post_id": post_id,
                    "original_owner": original_owner,
                    "attacker_id": attacker_user_id,
                    "issue": "Post modified without ownership check",
                    "status": put_response.status_code
                })
        
        if issues:
            pytest.fail(
                f"IDOR: Posts modifiable without ownership check:\n"
                + "\n".join([str(i) for i in issues])
            )
        
        print(f"\n[PASS] Post modification properly controlled")
    
    
    def test_parameter_tampering_user_id(self):
        """
        Test: Parameter tampering via userId field
        
        OWASP: A01:2021 - Broken Access Control
        Risk: High
        
        Scenario: Attacker creates a post with
        a different userId than their own,
        effectively posting as another user.
        
        Expected: Server should use authenticated
        user's ID, not client-provided userId
        """
        tampered_user_ids = [0, -1, 999999, 99999999]
        issues = []
        
        for tampered_id in tampered_user_ids:
            response = self.session.post(
                f"{self.base_url}/posts",
                json={
                    "title": "Parameter Tamper Test",
                    "body": "Testing userId tampering",
                    "userId": tampered_id
                },
                timeout=REQUEST_TIMEOUT
            )
            
            if response.status_code == 201:
                data = response.json()
                if data.get("userId") == tampered_id:
                    issues.append({
                        "tampered_userId": tampered_id,
                        "issue": "Server accepted tampered userId",
                        "status": response.status_code,
                        "response_userId": data.get("userId")
                    })
        
        if issues:
            pytest.fail(
                f"Parameter tampering vulnerability:\n"
                + "\n".join([str(i) for i in issues])
            )
        
        print(f"\n[PASS] Parameter tampering handled correctly")
    
    
    def test_mass_assignment_vulnerability(self):
        """
        Test: Mass Assignment vulnerability
        
        OWASP: A01:2021 - Broken Access Control
        Risk: High
        
        Scenario: Attacker sends extra fields
        hoping server will assign them to object.
        Example: Adding 'isAdmin: true' to POST body.
        
        Expected: Server ignores unknown fields
        """
        malicious_payloads = [
            {
                "title": "Normal Post",
                "body": "Normal body",
                "userId": 1,
                "isAdmin": True,           # Privilege escalation attempt
                "role": "admin",
                "permissions": ["all"]
            },
            {
                "title": "Normal Post",
                "body": "Normal body",
                "userId": 1,
                "id": 1,                   # Try to override ID
                "createdAt": "1970-01-01", # Try to set creation date
                "deletedAt": None          # Try to undelete
            }
        ]
        
        issues = []
        
        for payload in malicious_payloads:
            response = self.session.post(
                f"{self.base_url}/posts",
                json=payload,
                timeout=REQUEST_TIMEOUT
            )
            
            if response.status_code == 201:
                data = response.json()
                
                # Check if dangerous fields were assigned
                dangerous_fields = ["isAdmin", "role", "permissions"]
                for field in dangerous_fields:
                    if field in data and data[field]:
                        issues.append({
                            "field": field,
                            "value": data[field],
                            "issue": "Mass assignment vulnerability",
                        })
        
        if issues:
            pytest.fail(
                f"Mass assignment vulnerability found:\n"
                + "\n".join([str(i) for i in issues])
            )
        
        print(f"\n[PASS] Mass assignment properly blocked")
    
    
    def test_enumeration_attack(self):
        """
        Test: Resource enumeration attack
        
        OWASP: A01:2021 - Broken Access Control
        Risk: Medium
        
        Scenario: Attacker enumerates all users
        by incrementing IDs to harvest PII data.
        
        Expected: Rate limiting or auth should
        prevent bulk enumeration
        """
        harvested_data = []
        
        # Try to enumerate first 10 users
        for user_id in range(1, 11):
            response = self.session.get(
                f"{self.base_url}/users/{user_id}",
                timeout=REQUEST_TIMEOUT
            )
            
            if response.status_code == 200:
                data = response.json()
                harvested_data.append({
                    "id": user_id,
                    "name": data.get("name"),
                    "email": data.get("email"),
                    "phone": data.get("phone"),
                    "company": data.get("company", {}).get("name")
                })
        
        print(f"\n[Enumeration Audit]")
        print(f"Records harvested: {len(harvested_data)}")
        
        if harvested_data:
            print(f"  Sample data:")
            for record in harvested_data[:3]:
                print(f"    ID {record['id']}: "
                      f"{record['name']} | "
                      f"{record['email']}")
        
        # If we harvested more than 5 records = enumeration possible
        if len(harvested_data) >= 5:
            pytest.fail(
                f"ENUMERATION VULNERABILITY:\n"
                f"Successfully harvested {len(harvested_data)} "
                f"user records by incrementing IDs\n"
                f"PII exposed: name, email, phone, company\n"
                f"Fix: Implement authentication + rate limiting"
            )
        
        print(f"\n[PASS] Enumeration properly prevented")