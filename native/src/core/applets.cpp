#include <libgen.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <magisk.hpp>
#include <selinux.hpp>
#include <base.hpp>

using namespace std;

struct Applet {
    string_view name;
    int (*fn)(int, char *[]);
};

constexpr Applet applets[] = {
    { "su", su_client_main },
    { "resetprop", resetprop_main },
    { "magiskhide", denylist_cli },
};

int main(int argc, char *argv[]) {
    if (argc < 1)
        return 1;

    enable_selinux();
    cmdline_logging();
    init_argv0(argc, argv);

    string_view argv0 = basename(argv[0]);

    umask(0);

    if (argv0 == "magisk" || argv0 == "magisk32" || argv0 == "magisk64") {
        if (argc > 1 && argv[1][0] != '-') {
            // Calling applet with "magisk [applet] args..."
            --argc;
            ++argv;
            argv0 = argv[0];
        } else {
            return magisk_main(argc, argv);
        }
    }

    for (const auto &app : applets) {
        if (argv0 == app.name) {
            return app.fn(argc, argv);
        }
    }
    fprintf(stderr, "%s: applet not found\n", argv0.data());
    return 1;
}
