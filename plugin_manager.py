import importlib
import os
import sys
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional


class PluginInterface(ABC):
    def __init__(self):
        self._registry: Dict[str, PluginInterface] = {}

    # --- MANDATORY METADATA ---
    @property
    @abstractmethod
    def name(self) -> str:
        """Friendly display name of the plugin."""
        pass

    @property
    @abstractmethod
    def version(self) -> str:
        """Semantic versioning string (e.g. '1.0.0')."""
        pass

    @property
    @abstractmethod
    def author(self) -> str:
        """Author or maintainer name."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Brief summary of what security checks this plugin executes."""
        pass

    @property
    @abstractmethod
    def category(self) -> str:
        """High-level category (e.g., Storage, Identity, Compute)."""
        pass

    @property
    @abstractmethod
    def supported_services(self) -> List[str]:
        """AWS Services queried (e.g. ['s3'], ['iam', 'sts'])."""
        pass

    @property
    @abstractmethod
    def default_severity(self) -> str:
        """Default severity level (CRITICAL, HIGH, MEDIUM, LOW)."""
        pass

    @property
    def dependencies(self) -> List[str]:
        """Optional prerequisite plugins or services required to run."""
        return []

    # --- EXECUTION ENGINE ---
    @abstractmethod
    def execute(self, context: Dict[str, Any]) -> list:
        """Core execution logic returning list of Finding objects."""
        pass

    # --- HELPER METADATA EXPORT ---
    def get_metadata(self) -> Dict[str, Any]:
        """Returns structured metadata dictionary for CLI displays/JSON exports."""
        return {
            "name": self.name,
            "version": self.version,
            "author": self.author,
            "description": self.description,
            "category": self.category,
            "supported_services": self.supported_services,
            "severity": self.default_severity,
            "dependencies": self.dependencies,
        }


class PluginRegistry:
    def __init__(self):
        self._registry: Dict[str, PluginInterface] = {}

    def register(self, plugin: PluginInterface):
        key = plugin.name.lower().replace(" ", "_")
        self._registry[key] = plugin

    def get(self, name: str) -> Optional[PluginInterface]:
        return self._registry.get(name)

    def list_metadata(self):
        """Prints a structured CLI table of all registered plugins."""
        print("\n" + "=" * 65)
        print("  REGISTERED CLOUDGUARD PLUGINS")
        print("=" * 65)

        if not self._registry:
            print(" No plugins loaded.")
            return

        for key, plugin in self._registry.items():
            meta = plugin.get_metadata()
            deps = (
                ", ".join(meta["dependencies"])
                if meta["dependencies"]
                else "None"
            )
            services = ", ".join(meta["supported_services"]).upper()

            print(f"\n{meta['name']} (v{meta['version']})")
            print(f"   ├─ ID          : {key}")
            print(f"   ├─ Author      : {meta['author']}")
            print(f"   ├─ Category    : {meta['category']} [{services}]")
            print(f"   ├─ Severity    : {meta['severity']}")
            print(f"   ├─ Deps        : {deps}")
            print(f"   └─ Description : {meta['description']}")

        print("\n" + "=" * 65)
        print(f" Total Plugins Registered: {len(self._registry)}\n")


def load_all_plugins(registry: PluginRegistry):
    base_dir = os.path.dirname(os.path.abspath(__file__))
    if base_dir not in sys.path:
        sys.path.insert(0, base_dir)

    plugins_dir = os.path.join(base_dir, "plugins")

    if not os.path.exists(plugins_dir):
        print(f"[!] Plugins directory not found at: {plugins_dir}")
        return

    for root, _, files in os.walk(plugins_dir):
        for file in files:
            if file.endswith(".py") and not file.startswith("__"):
                rel_path = os.path.relpath(os.path.join(root, file), base_dir)
                module_name = rel_path[:-3].replace(os.sep, ".")

                try:
                    module = importlib.import_module(module_name)
                    if hasattr(module, "Plugin"):
                        plugin_class = getattr(module, "Plugin")
                        registry.register(plugin_class())
                except Exception as e:
                    print(f"[!] Error loading plugin '{file}': {e}")


if __name__ == "__main__":
    from cloudguard.aws.session import create_session

    session = create_session()
    registry = PluginRegistry()
    load_all_plugins(registry)

    registry.list_metadata()

    context = {
        "session": session,
        "s3_client": session.client("s3"),
        "iam_client": session.client("iam"),
    }

    print("Running Registered Plugins...\n")
    for name, plugin in registry._registry.items():
        print(f" Running --> [{plugin.category.upper()}] {plugin.name}")
        findings = plugin.execute(context)
        print(f"  └─ Findings count: {len(findings) if findings else 0}")

    print("\nAll Plugins Finished Successfully.")