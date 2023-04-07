#include <sys/wait.h>
#include <sys/mount.h>
#include <string>

#include <magisk.hpp>
#include <base.hpp>
#include <daemon.hpp>

#include "deny.hpp"

#define hide_version 3

using namespace std;

[[noreturn]] static void usage() {
    fprintf(stderr,
R"EOF(SuList Config CLI
Usage: magisk --sulist [action [arguments...] ]
Actions:
   status          Return the SuList status
   add PKG [PROC]  Add a new target to the sulist
   rm PKG [PROC]   Remove target(s) from the sulist
   ls              Print the current sulist
   exec CMDs...    Execute commands in isolated mount
                   namespace and do all unmounts
Magisk Delta specific Actions:
   version         Print MagiskHide version
   --do-unmount [PID...]
                   Unmount all Magisk modifications
                   directly [in another namespace...]
)EOF");
    exit(1);
}

void denylist_handler(int client, const sock_cred *cred) {
    if (client < 0) {
        revert_daemon(1, -client);
        return;
    }

    int req = read_int(client);
    int res = DenyResponse::ERROR;

    switch (req) {
	case DenyRequest::ADD:
        res = add_list(client);
        break;
    case DenyRequest::REMOVE:
        res = rm_list(client);
        break;
    case DenyRequest::LIST:
        ls_list(client);
        return;
    case DenyRequest::STATUS:
        if (denylist_enforced && do_unmount){
        	res = DenyResponse::ENFORCED;
		} else res = DenyResponse::NOT_ENFORCED;
        break;
    default:
        // Unknown request code
        break;
    }
    write_int(client, res);
    close(client);
}

int denylist_cli(int argc, char **argv) {
    if (argc < 2)
        usage();

    int req;
    if (argv[1] == "status"sv)
        req = DenyRequest::STATUS;
    else if (argv[1] == "add"sv){
    	req = DenyRequest::ADD;
    } else if (argv[1] == "rm"sv){
    	req = DenyRequest::REMOVE;
    } else if (argv[1] == "ls"sv)
        req = DenyRequest::LIST;
    else if (argv[1] == "version"sv) {
        printf("MAGISKHIDE:%d\n", hide_version);
        return 0;
    } else if (argv[1] == "--do-unmount"sv) {
        int fd = connect_daemon(MainRequest::GET_PATH);
        MAGISKTMP = read_string(fd);
        close(fd);
        if (argc > 2) {
            for (int num=3; num<=argc; num++) {
                int processid=atoi(argv[num-1]);
                revert_unmount(processid);
            }
        } else revert_unmount(-1);
        exit(0);
    } else if (argv[1] == "exec"sv && argc > 2) {
        switch_mnt_ns(1);
        xunshare(CLONE_NEWNS);
        xmount(nullptr, "/", nullptr, MS_PRIVATE | MS_REC, nullptr);
        int fd = connect_daemon(MainRequest::GET_PATH);
        MAGISKTMP = read_string(fd);
        close(fd);
        revert_unmount(-1);
        execvp(argv[2], argv + 2);
        exit(1);
    } else {
        usage();
    }

    // Send request
    int fd = connect_daemon(MainRequest::DENYLIST);
    write_int(fd, req);
    if (req == DenyRequest::ADD || req == DenyRequest::REMOVE) {
        write_string(fd, argv[2]);
        write_string(fd, argv[3] ? argv[3] : "");
    }

    // Get response
    int res = read_int(fd);
    if (res < 0 || res >= DenyResponse::END)
        res = DenyResponse::ERROR;
    switch (res) {
    case DenyResponse::NOT_ENFORCED:
        fprintf(stderr, "SuList is not working\n");
        return 1;
    case DenyResponse::ENFORCED:
    	fprintf(stderr, "SuList is working\n");
        return 0;
    case DenyResponse::ITEM_EXIST:
        fprintf(stderr, "Target already exists in sulist\n");
        goto return_code;
    case DenyResponse::ITEM_NOT_EXIST:
        fprintf(stderr, "Target does not exist in sulist\n");
        goto return_code;
    case DenyResponse::NO_NS:
        fprintf(stderr, "The kernel does not support mount namespace\n");
        goto return_code;
    case DenyResponse::INVALID_PKG:
        fprintf(stderr, "Invalid package / process name\n");
        goto return_code;
    case DenyResponse::ERROR:
        fprintf(stderr, "hide: Daemon error\n");
        return -1;
    case DenyResponse::SULIST_NO_DISABLE:
        fprintf(stderr, "MagiskHide cannot be disabled because SuList is enforced\n");
        return -1;
    case DenyResponse::OK:
        break;
    default:
        __builtin_unreachable();
    }

    if (req == DenyRequest::LIST) {
        string out;
        for (;;) {
            read_string(fd, out);
            if (out.empty())
                break;
            printf("%s\n", out.data());
        }
    }

return_code:
    return req == DenyRequest::STATUS ? res != DenyResponse::ENFORCED : res != DenyResponse::OK;
}
