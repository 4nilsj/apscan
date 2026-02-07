import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, AsyncMock
from apscan.server.main import app
from apscan.server.manager import ScanManager

client = TestClient(app)

# --- GET /api/rules ---

def test_list_rules_empty():
    """Test listing rules when there are none."""
    with patch.object(ScanManager, 'get_instance') as mock_instance:
        mock_manager = mock_instance.return_value
        mock_manager.get_all_rules.return_value = []
        
        # Override dependency in app if necessary, but here we patch the global manager instance used in main.py
        # Actually main.py initializes `manager = ScanManager.get_instance()` at module level.
        # Patching `apscan.server.main.manager` is safer.
        pass

def test_list_rules_mocked():
    """Test listing rules with mock data."""
    with patch("apscan.server.main.manager") as mock_manager:
        mock_manager.get_all_rules.return_value = [
            {"id": "1", "name": "Existing Rule", "severity": "HIGH"}
        ]
        
        response = client.get("/api/rules")
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert data[0]["name"] == "Existing Rule"

# --- POST /api/rules ---

@pytest.mark.asyncio
async def test_create_rule():
    """Test creating a new rule."""
    new_rule = {
        "name": "New Test Rule",
        "description": "Test checking",
        "severity": "MEDIUM",
        "request": {"method": "GET", "path": "/api/test"},
        "match": {"status": 200}
    }
    
    # Needs AsyncMock for async method save_custom_rule
    mock_save = AsyncMock(return_value="rule-abc-123")
    
    with patch("apscan.server.main.manager") as mock_manager:
        mock_manager.save_custom_rule = mock_save
        
        response = client.post("/api/rules", json=new_rule)
        
        assert response.status_code == 200
        assert response.json() == {"id": "rule-abc-123", "message": "Rule saved successfully"}
        
        # Verify call args
        mock_save.assert_called_once()
        args = mock_save.call_args[0][0]
        assert args["name"] == "New Test Rule"

# --- DELETE /api/rules/{id} ---

@pytest.mark.asyncio
async def test_delete_rule_success():
    """Test deleting an existing rule."""
    mock_delete = AsyncMock(return_value=True)
    
    with patch("apscan.server.main.manager") as mock_manager:
        mock_manager.delete_custom_rule = mock_delete
        
        response = client.delete("/api/rules/rule-123")
        
        assert response.status_code == 200
        assert response.json() == {"message": "Rule deleted"}
        mock_delete.assert_called_with("rule-123")

@pytest.mark.asyncio
async def test_delete_rule_not_found():
    """Test deleting a non-existent rule."""
    mock_delete = AsyncMock(return_value=False)
    
    with patch("apscan.server.main.manager") as mock_manager:
        mock_manager.delete_custom_rule = mock_delete
        
        response = client.delete("/api/rules/missing-rule")
        
        assert response.status_code == 404
        assert response.json()["detail"] == "Rule not found"
