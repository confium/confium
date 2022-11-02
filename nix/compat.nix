let
  src = (builtins.fromJSON (builtins.readFile ../flake.lock)).nodes.flake-compat.locked;
in
import
  (fetchTarball {
    url = "https://github.com/edolstra/flake-compat/archive/${src.rev}.tar.gz";
    sha256 = src.narHash;
  })
