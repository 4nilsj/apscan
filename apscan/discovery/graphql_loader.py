import httpx
import logging
from typing import List, Dict, Any
from urllib.parse import urljoin

from apscan.core.context import APIEndpoint

logger = logging.getLogger(__name__)

INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    types {
      ...FullType
    }
  }
}

fragment FullType on __Type {
  kind
  name
  fields(includeDeprecated: true) {
    name
    args {
      name
      type {
        ...TypeRef
      }
    }
  }
}

fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
      }
    }
  }
}
"""

class GraphQLLoader:
    def __init__(self, target_url: str):
        self.target_url = target_url

    async def load(self) -> List[APIEndpoint]:
        """
        Loads GraphQL schema via introspection and converts operations to APIEndpoint objects.
        """
        logger.info(f"Attempting GraphQL introspection at {self.target_url}")
        
        async with httpx.AsyncClient(verify=False) as client:
            try:
                response = await client.post(
                    self.target_url,
                    json={"query": INTROSPECTION_QUERY},
                    timeout=10.0
                )
                
                if response.status_code != 200:
                    logger.error(f"GraphQL introspection failed with status {response.status_code}")
                    return []
                
                data = response.json()
                if "errors" in data:
                    logger.error(f"GraphQL introspection returned errors: {data['errors']}")
                    return []
                
                schema = data.get("data", {}).get("__schema")
                if not schema:
                    logger.error("No schema found in GraphQL response")
                    return []
                    
                return self._parse_schema(schema)
                
            except httpx.RequestError as e:
                logger.error(f"Network error during GraphQL introspection: {e}")
                return []
            except Exception as e:
                logger.error(f"Error loading GraphQL schema: {e}")
                return []

    def _parse_schema(self, schema: Dict[str, Any]) -> List[APIEndpoint]:
        endpoints = []
        types_map = {t['name']: t for t in schema.get('types', []) if t.get('name')}
        
        # Parse Queries
        query_type_name = schema.get('queryType', {}).get('name')
        if query_type_name and query_type_name in types_map:
            for field in types_map[query_type_name].get('fields', []) or []:
                endpoints.append(self._create_endpoint(field, "QUERY"))

        # Parse Mutations
        mutation_type_name = schema.get('mutationType', {}).get('name')
        if mutation_type_name and mutation_type_name in types_map:
            for field in types_map[mutation_type_name].get('fields', []) or []:
                endpoints.append(self._create_endpoint(field, "MUTATION"))

        logger.info(f"Discovered {len(endpoints)} GraphQL operations")
        return endpoints

    def _create_endpoint(self, field: Dict[str, Any], op_type: str) -> APIEndpoint:
        """
        Creates an APIEndpoint representing a GraphQL field.
        We simulate it as a POST request to the endpoint with the operation name as a query param
        so our existing rules can verify it, though GQL is technically always POST /graphql.
        """
        op_name = field['name']
        # We construct a synthetic path to represent the operation
        # e.g. /graphql?operation=getUser
        synthetic_path = f"{self.target_url}?{op_type.lower()}={op_name}"
        
        # Extract arguments as parameters
        params = []
        for arg in field.get('args', []):
            params.append({
                "name": arg['name'],
                "in": "body", # All args are in the JSON body
                "schema": {"type": "string"} # Simplified for MVP
            })

        return APIEndpoint(
            path=self.target_url,
            method="POST",
            params=params,
            description=f"GraphQL {op_type}: {op_name}",
            # Store metadata for GraphQL-specific rules
            metadata={
                "graphql_operation": op_name,
                "graphql_type": op_type,
                "graphql_args": params
            }
        )
