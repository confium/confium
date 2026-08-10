#include "utest.h"
#include <string>
#include <vector>
#include <cstdlib>
#include <confium.h>
#include <toml.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/lexical_cast.hpp>

std::string cargo_version_string() {
    const char *cargo_toml_env = getenv("CONFIUM_CARGO_TOML");
    std::string cargo_toml_path(cargo_toml_env ? cargo_toml_env : "");
    auto cargo_toml = toml::parse(cargo_toml_path);
    auto package = toml::find(cargo_toml, "package");
    auto &pkg_table = package.as_table();

    // Check if version uses workspace inheritance: version.workspace = true
    // In that case "version" in [package] is a table, not a string,
    // and the real version lives in the workspace root's [workspace.package].
    auto it = pkg_table.find("version");
    if (it != pkg_table.end() && it->second.is_table()) {
        // Walk up to find the workspace root Cargo.toml.
        // crate_dir = crates/confium-core/ → workspace root = ../..
        std::string crate_dir = cargo_toml_path.substr(0, cargo_toml_path.find_last_of('/'));
        std::string crates_dir = crate_dir.substr(0, crate_dir.find_last_of('/'));
        std::string workspace_root = crates_dir.substr(0, crates_dir.find_last_of('/'));
        std::string ws_toml_path = workspace_root + "/Cargo.toml";
        auto ws_toml = toml::parse(ws_toml_path);
        auto ws_package = toml::find(ws_toml, "workspace", "package");
        return toml::find<std::string>(ws_package, "version");
    }
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

