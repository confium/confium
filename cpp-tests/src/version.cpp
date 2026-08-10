#include "utest.h"
#include <string>
#include <vector>
#include <cstdlib>
#include <confium.h>
#include <toml.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/lexical_cast.hpp>
#include <filesystem>

std::string cargo_version_string() {
    auto cargo_toml_path = std::string(getenv("CONFIUM_CARGO_TOML"));
    auto cargo_toml = toml::parse(cargo_toml_path);
    auto package = toml::find(cargo_toml, "package");

    // Check if version uses workspace inheritance: version.workspace = true
    // In that case the "version" key in [package] is a table, not a string,
    // and the real version lives in the workspace root's [workspace.package].
    auto version_node = package.as_table()->find("version");
    if (version_node != package.as_table()->end()) {
        if (version_node->second.is_table()) {
            // version = { workspace = true } — resolve from workspace root.
            auto crate_dir = std::filesystem::path(cargo_toml_path).parent_path();
            auto workspace_root = crate_dir.parent_path().parent_path();
            auto workspace_toml = toml::parse((workspace_root / "Cargo.toml").string());
            auto ws_package = toml::find(workspace_toml, "workspace", "package");
            return toml::find<std::string>(ws_package, "version");
        }
        return version_node->second.as_string();
    }
    // Fallback: direct string version.
    return toml::find<std::string>(package, "version");
}

UTEST(version, string) {
    auto cargo_version(cargo_version_string());
    char *version = NULL;
    ASSERT_EQ(0, cfm_version_string(&version));
    ASSERT_STREQ(version, cargo_version.c_str());
}

UTEST(version, major_minor_patch) {
    using boost::algorithm::split;
    using boost::algorithm::is_any_of;
    using boost::lexical_cast;
    auto cargo_version(cargo_version_string());
    std::vector<std::string> components;
    split(components, cargo_version, is_any_of("."));
    ASSERT_EQ(cfm_version_major(), lexical_cast<uint32_t>(components[0]));
    ASSERT_EQ(cfm_version_minor(), lexical_cast<uint32_t>(components[1]));
    ASSERT_EQ(cfm_version_patch(), lexical_cast<uint32_t>(components[2]));
}

