#include "utest.h"
#include <string>
#include <vector>
#include <cstdlib>
#include <confium.h>
#include <toml.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/lexical_cast.hpp>

std::string cargo_version_string() {
    auto cargo_toml = toml::parse(getenv("CONFIUM_CARGO_TOML"));
    auto package = toml::find(cargo_toml, "package");
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

