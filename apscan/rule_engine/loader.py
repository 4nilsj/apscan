import pkgutil
import importlib
import inspect
import os
from typing import List
from apscan.core.rule import ScannerRule
import apscan.rules as rules_package # Base package for rules

class RuleLoader:
    def __init__(self):
        self.rules: List[ScannerRule] = []

    def load_rules(self) -> List[ScannerRule]:
        """Loads both Python and YAML rules."""
        self.load_python_rules()
        self.load_yaml_rules()
        return self.rules

    def load_python_rules(self):
        """Discovers and loads rule classes from the apscan.rules package."""
        path = rules_package.__path__ # Use __path__ for package walking
        prefix = rules_package.__name__ + "."
        
        # Walk through the package
        for _, name, _ in pkgutil.walk_packages(path, prefix=prefix):
            try:
                module = importlib.import_module(name)
                
                # inspect module members
                for _, obj in inspect.getmembers(module):
                    if inspect.isclass(obj) and issubclass(obj, ScannerRule) and obj is not ScannerRule:
                        # Instantiate and add
                        rule = obj()
                        if not any(r.id == rule.id for r in self.rules):
                            self.rules.append(rule)
                            
            except Exception as e:
                print(f"[!] Failed to load rule module {name}: {e}")

    def load_plugins(self, plugin_dir: str):
        """Loads custom python rules from a directory."""
        if not os.path.exists(plugin_dir):
            print(f"[!] Plugin directory not found: {plugin_dir}")
            return
            
        print(f"[*] Loading plugins from {plugin_dir}...")
        import importlib.util

        for root, _, files in os.walk(plugin_dir):
            for file in files:
                if file.endswith(".py") and not file.startswith("__"):
                    full_path = os.path.join(root, file)
                    try:
                        # Dynamic Import
                        spec = importlib.util.spec_from_file_location("custom_rule", full_path)
                        if spec and spec.loader:
                            module = importlib.util.module_from_spec(spec)
                            spec.loader.exec_module(module)
                            
                            # Inspect and Register
                            count = 0
                            for _, obj in inspect.getmembers(module):
                                if inspect.isclass(obj) and issubclass(obj, ScannerRule) and obj is not ScannerRule:
                                    rule = obj()
                                    if not any(r.id == rule.id for r in self.rules):
                                        self.rules.append(rule)
                                        count += 1
                            if count > 0:
                                print(f"    [+] Loaded {count} rules from {file}")
                                
                    except Exception as e:
                        print(f"[!] Failed to load plugin {file}: {e}")

    def load_yaml_rules(self):
        """Scans the rules directory for .yaml files."""
        try:
            import yaml
            from apscan.rule_engine.yaml_rule import YAMLRule
        except ImportError:
            print("[!] PyYAML not installed. Skipping YAML rules.")
            return

        base_path = os.path.dirname(rules_package.__file__)
        
        for root, dirs, files in os.walk(base_path):
            for file in files:
                if file.endswith(".yaml") or file.endswith(".yml"):
                    full_path = os.path.join(root, file)
                    try:
                        with open(full_path, 'r') as f:
                            doc = yaml.safe_load(f)
                            if not doc or 'id' not in doc:
                                continue
                            
                            rule = YAMLRule(doc)
                            if not any(r.id == rule.id for r in self.rules):
                                self.rules.append(rule)
                                # print(f"[*] Loaded YAML rule: {rule.name}")
                    except Exception as e:
                        print(f"[!] Failed to load YAML rule {file}: {e}")
