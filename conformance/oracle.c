//go:build ignore

/* Reference driver: uses only libpeios' public C ABI. */
#include <peios.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>

static void dump(const void *p, size_t n) {
    const unsigned char *b = p;
    for (size_t i = 0; i < n; i++) printf("%02x", b[i]);
    putchar('\n');
}
static size_t unhex(const char *s, unsigned char *b) {
    size_t n = strlen(s) / 2;
    for (size_t i = 0; i < n; i++) {
        unsigned x = 0;
        sscanf(s + 2 * i, "%2x", &x);
        b[i] = (unsigned char)x;
    }
    return n;
}
static int extra(const char *mode, char *arg) {
    unsigned char b[131072];
    ssize_t n;
    if (!strcmp(mode, "label-selector")) {
        printf("%u %u %u\n", KACS_SECINFO_LABEL, KACS_SECINFO_LABEL | KACS_SECINFO_OWNER,
               KACS_SECINFO_LABEL | KACS_SECINFO_DACL);
        return 1;
    }
    if (!strcmp(mode, "native-guid")) {
        int fd = peios_token_open_self(0, KACS_TOKEN_QUERY);
        unsigned char guid[16], raw[16], untouched[16];
        if (fd < 0 || peios_token_guid(fd, guid) != 0 ||
            peios_token_query(fd, KACS_TOKEN_CLASS_GUID, raw, sizeof raw) != 16 ||
            memcmp(guid, raw, sizeof guid) != 0) {
            puts("error");
            return 1;
        }
        close(fd);
        memset(untouched, 0xa5, sizeof untouched);
        memcpy(raw, untouched, sizeof raw);
        if (peios_token_guid(-1, raw) != -1 || errno != EBADF ||
            memcmp(raw, untouched, sizeof raw) != 0 || peios_token_guid(-1, NULL) != -1 ||
            errno != EINVAL) {
            puts("error");
            return 1;
        }
        fd = peios_token_open_self(0, KACS_TOKEN_QUERY_SOURCE);
        if (fd < 0 || peios_token_guid(fd, raw) != -1 || errno != EACCES ||
            memcmp(raw, untouched, sizeof raw) != 0) {
            puts("error");
            return 1;
        }
        close(fd);
        puts("ok");
        return 1;
    }

    if (!strcmp(mode, "native-sysv")) {
        char *sep = strchr(arg, '|');
        if (!sep) return 1;
        *sep++ = 0;
        uint32_t kinds[] = {KACS_SD_AT_SYSV_SHM, KACS_SD_AT_SYSV_MSG, KACS_SD_AT_SYSV_SEM};
        n = peios_sysv_get_sd(kinds[atoi(arg)], atoi(sep),
                              OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION |
                                  DACL_SECURITY_INFORMATION,
                              b, sizeof b);
        if (n < 0) puts("error");
        else dump(b, n);
        return 1;
    }
    if (!strcmp(mode, "native-mount")) {
        int fd = open(arg, 0x200000 | O_CLOEXEC);
        struct peios_mount_policy p = {0};
        n = peios_mount_get_policy(fd, &p, b, sizeof b);
        close(fd);
        if (n < 0) puts("error");
        else {
            printf("%u %u %u ", p.policy, p.flags, p.generation);
            dump(b, p.template_sd_len);
        }
        return 1;
    }
    if (!strcmp(mode, "socket")) {
        int socks[2];
        if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, socks) < 0) return 1;
        int null = open("/dev/null", O_RDONLY | O_CLOEXEC), fds[2] = {null, null}, received[2];
        char buf[1];
        unsigned cap = atoi(arg);
        size_t len = cap == 3 ? 0 : 5;
        const char *payload = "hello";
        ssize_t sent = peios_socket_send_message(socks[0], payload, len, -1, fds, 2, 0);
        struct peios_socket_message m = {
            .token_fd = -1, .fds = received, .fd_cap = cap == 3 ? 2 : cap};
        ssize_t got = peios_socket_recv_message(socks[1], buf, cap == 3 ? 0 : 1, &m, 0);
        printf("%zd %zd %u %u\n", sent, got, m.fd_count, m.flags);
        for (unsigned j = 0; j < m.fd_count; j++) close(received[j]);
        if (m.token_fd >= 0) close(m.token_fd);
        close(null);
        close(socks[0]);
        close(socks[1]);
        return 1;
    }
    if (!strcmp(mode, "token-extra")) {
        peios_token_builder *t = peios_token_builder_new();
        unsigned char sid[68];
        ssize_t sn = peios_sid_parse_string(sid, sizeof sid, "SY");
        peios_token_builder_user(t, sid, sn);
        if (!strcmp(arg, "empty")) {
            uint16_t types[] = {1, 2, 3, 5, 6, 16};
            for (unsigned i = 0; i < 6; i++) {
                struct peios_token_claim c = {.name = "empty", .value_type = types[i]};
                peios_token_builder_add_user_claim(t, &c);
            }
        } else {
            unsigned count = atoi(arg);
            for (unsigned i = 0; i < count; i++) peios_token_builder_add_group(t, sid, sn, 7);
        }
        const void *out;
        n = peios_token_builder_bytes(t, &out);
        if (n < 0) puts("error");
        else dump(out, n);
        peios_token_builder_free(t);
        return 1;
    }
    if (!strcmp(mode, "ring")) {
        int fd = open(arg, O_RDWR | O_CLOEXEC);
        struct peios_event_ring r = {0};
        if (fd < 0 || peios_event_ring_map(fd, 256, &r) < 0) {
            puts("error");
            if (fd >= 0) close(fd);
            return 1;
        }
        close(fd);
        uint64_t pos = peios_event_ring_tail_pos(&r);
        printf("%llu %llu %llu %llu ", (unsigned long long)peios_event_ring_capacity(&r),
               (unsigned long long)pos, (unsigned long long)peios_event_ring_write_pos(&r),
               (unsigned long long)peios_event_ring_generation(&r));
        peios_event_ring_set_need_wake(&r, 1);
        peios_event_ring_set_need_wake(&r, 0);
        struct peios_event ev;
        ssize_t n = peios_event_ring_event_at(&r, pos, &ev);
        if (n < 0) printf("error\n");
        else {
            printf("%zd %llu %d ", n, (unsigned long long)ev.sequence,
                   peios_event_ring_wait(&r, pos, 0));
            dump(ev.payload, ev.payload_len);
        }
        peios_event_ring_unmap(&r);
        return 1;
    }
    if (!strcmp(mode, "mp-cursor")) {
        char *sep = strchr(arg, '|');
        if (!sep) return 1;
        *sep++ = 0;
        n = unhex(sep, b);
        struct peios_mp_reader r;
        peios_mp_reader_init(&r, b, n);
        int kind = peios_mp_peek(&r);
        printf("%d ", kind);
        ssize_t rc = -1;
        char result[128] = "";
        const void *bytes = NULL;
        size_t len = 0;
        if (!strcmp(arg, "nil")) rc = peios_mp_read_nil(&r);
        if (!strcmp(arg, "bool")) {
            bool v = false;
            rc = peios_mp_read_bool(&r, &v);
            snprintf(result, sizeof result, "%d", v);
        }
        if (!strcmp(arg, "int")) {
            int64_t v = 0;
            rc = peios_mp_read_int(&r, &v);
            snprintf(result, sizeof result, "%lld", (long long)v);
        }
        if (!strcmp(arg, "uint")) {
            uint64_t v = 0;
            rc = peios_mp_read_uint(&r, &v);
            snprintf(result, sizeof result, "%llu", (unsigned long long)v);
        }
        if (!strcmp(arg, "float")) {
            double v = 0;
            uint64_t bits;
            rc = peios_mp_read_float(&r, &v);
            memcpy(&bits, &v, 8);
            snprintf(result, sizeof result, "%016llx", (unsigned long long)bits);
        }
        if (!strcmp(arg, "str")) {
            const char *v = NULL;
            rc = peios_mp_read_str(&r, &v);
            bytes = v;
            if (rc >= 0) len = rc;
        }
        if (!strcmp(arg, "bin")) {
            rc = peios_mp_read_bin(&r, &bytes);
            if (rc >= 0) len = rc;
        }
        if (!strcmp(arg, "ext")) {
            int8_t typ = 0;
            rc = peios_mp_read_ext(&r, &typ, &bytes);
            if (rc >= 0) len = rc;
            snprintf(result, sizeof result, "%d:", typ);
        }
        if (!strcmp(arg, "array")) {
            rc = peios_mp_read_array(&r);
            snprintf(result, sizeof result, "%zd", rc);
        }
        if (!strcmp(arg, "map")) {
            rc = peios_mp_read_map(&r);
            snprintf(result, sizeof result, "%zd", rc);
        }
        if (!strcmp(arg, "skip")) rc = peios_mp_skip(&r);
        if (rc < 0) printf("error %zu\n", peios_mp_reader_remaining(&r));
        else {
            printf("ok %zu %s", peios_mp_reader_remaining(&r), result);
            if (bytes) dump(bytes, len);
            else putchar('\n');
        }
        return 1;
    }
    if (!strcmp(mode, "mp-depth")) {
        char *sep = strchr(arg, '|');
        if (!sep) return 1;
        *sep++ = 0;
        n = unhex(sep, b);
        puts(peios_mp_validate(b, n, strtoul(arg, NULL, 10)) == 0 ? "ok" : "error");
        return 1;
    }
    if (!strcmp(mode, "sd-validate")) {
        n = unhex(arg, b);
        peios_sd_view v;
        puts(peios_sd_parse(b, n, &v) == 0 ? "ok" : "error");
        return 1;
    }
    if (!strcmp(mode, "acl-validate")) {
        n = unhex(arg, b);
        peios_acl_view v;
        puts(peios_acl_parse(b, n, &v) == 0 ? "ok" : "error");
        return 1;
    }
    if (!strcmp(mode, "mp-validate") || !strcmp(mode, "audit-validate")) {
        if (strlen(arg) > sizeof(b) * 2) {
            puts("error");
            return 1;
        }
        n = unhex(arg, b);
        int rc = !strcmp(mode, "mp-validate") ? peios_mp_validate(b, n, 32)
                                              : peios_audit_context_validate(b, n);
        puts(rc == 0 ? "ok" : "error");
        return 1;
    }
    if (!strcmp(mode, "mp-fixture")) {
        peios_mp_writer *w = peios_mp_writer_new();
        peios_mp_write_array(w, 10);
        peios_mp_write_nil(w);
        peios_mp_write_bool(w, true);
        peios_mp_write_int(w, -129);
        peios_mp_write_uint(w, UINT64_MAX);
        peios_mp_write_float(w, 1.5);
        peios_mp_write_str(w, "hello", 5);
        peios_mp_write_bin(w, "abc", 3);
        peios_mp_write_ext(w, -1, "xy", 2);
        peios_mp_write_map(w, 1);
        peios_mp_write_str(w, "n", 1);
        peios_mp_write_int(w, 128);
        peios_mp_write_array(w, 0);
        const void *out;
        n = peios_mp_writer_bytes(w, &out);
        if (n < 0) puts("error");
        else dump(out, n);
        peios_mp_writer_free(w);
        return 1;
    }
    if (!strcmp(mode, "audit")) {
        struct peios_audit_field fields[] = {
            {.key = "name", .value_type = PEIOS_AUDIT_STR, .bytes = "sdk", .len = 3},
            {.key = "id", .value_type = PEIOS_AUDIT_UINT, .scalar = 300},
            {.key = "ok", .value_type = PEIOS_AUDIT_BOOL, .scalar = 1}};
        n = peios_audit_context_encode(arg, fields, 3, b, sizeof b);
        if (n < 0) puts("error");
        else dump(b, n);
        return 1;
    }
    if (!strcmp(mode, "inherit") || !strcmp(mode, "strip")) {
        char *parent = strtok(arg, "|"), *child = strtok(NULL, "|"), *container = strtok(NULL, "|");
        unsigned char p[65535], c[65535];
        ssize_t pn = peios_sddl_parse_sd(p, sizeof p, parent);
        if (pn < 0) {
            puts("error");
            return 1;
        }
        if (!strcmp(mode, "strip"))
            n = peios_sd_strip_inherited(b, sizeof b, p, pn,
                                         DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION);
        else {
            ssize_t cn = peios_sddl_parse_sd(c, sizeof c, child);
            if (cn < 0) {
                puts("error");
                return 1;
            }
            n = peios_sd_reinherit_ex(b, sizeof b, p, pn, c, cn, atoi(container),
                                      &peios_file_generic_mapping,
                                      DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION);
        }
        if (n < 0) puts("error");
        else dump(b, n);
        return 1;
    }
    if (!strcmp(mode, "token-spec")) {
        unsigned char sid[68];
        ssize_t sn = peios_sid_parse_string(sid, sizeof sid, "SY");
        peios_token_builder *t = peios_token_builder_new();
        peios_token_builder_user(t, sid, sn);
        peios_token_builder_add_group(t, sid, sn, 7);
        peios_token_builder_privileges(t, 3, 1);
        peios_token_builder_type(t, 1, 2);
        peios_token_builder_integrity(t, 8192);
        peios_token_builder_projected_ids(t, 42, 43);
        peios_token_builder_expiration(t, 99);
        peios_token_builder_source(t, "sdk\0\0\0\0\0", 17);
        uint32_t gids[] = {1, 2};
        peios_token_builder_supp_gids(t, gids, 2);
        if (!strcmp(arg, "full")) {
            peios_token_builder_add_device_group(t, sid, sn, 7);
            peios_token_builder_add_restricted_sid(t, sid, sn, 4);
            peios_token_builder_confinement(t, sid, sn);
            struct peios_token_flags flags = {.write_restricted = true,
                                              .user_deny_only = true,
                                              .isolation_boundary = true,
                                              .confinement_exempt = true};
            peios_token_builder_flags(t, &flags);
            unsigned char acl[8] = {2, 0, 8, 0, 0, 0, 0, 0};
            peios_token_builder_default_dacl(t, acl, sizeof acl);
            struct peios_token_claim_value vs[] = {{.scalar = (uint64_t)-9},
                                                   {.scalar = 300},
                                                   {.scalar = 1},
                                                   {.bytes = "hello", .len = 5},
                                                   {.bytes = sid, .len = (size_t)sn},
                                                   {.bytes = "abc", .len = 3}};
            uint16_t types[] = {1, 2, 6, 3, 5, 16};
            for (size_t i = 0; i < 6; i++) {
                struct peios_token_claim c = {.name = "claim",
                                              .value_type = types[i],
                                              .flags = 0,
                                              .values = &vs[i],
                                              .value_count = 1};
                peios_token_builder_add_user_claim(t, &c);
                peios_token_builder_add_device_claim(t, &c);
            }
            unsigned char guid[1][16] = {{1}};
            const char *layers[] = {"private"};
            struct peios_token_lcs_credentials creds = {.scope_guids = guid,
                                                        .scope_count = 1,
                                                        .private_layers = layers,
                                                        .private_layer_count = 1};
            peios_token_builder_lcs_credentials(t, &creds);
        }
        const void *out;
        n = peios_token_builder_bytes(t, &out);
        if (n < 0) puts("error");
        else dump(out, n);
        peios_token_builder_free(t);
        return 1;
    }
    if (!strcmp(mode, "native-access")) {
        n = peios_sddl_parse_sd(b, sizeof b, arg);
        if (n < 0) {
            puts("error");
            return 1;
        }
        struct peios_access_request req = {
            .token_fd = -1, .sd = b, .sd_len = n, .desired = 1, .mapping = {1, 2, 4, 7}};
        uint32_t granted = 0;
        int rc = peios_access_check(&req, &granted, NULL);
        if (rc < 0 && errno != EACCES) {
            puts("error");
            return 1;
        }
        printf("%d %u\n", rc == 0, granted);
        return 1;
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 3) return 2;
    if (extra(argv[1], argv[2])) return 0;
    if (!strcmp(argv[1], "native-file")) {
        unsigned char b[65535];
        ssize_t n = peios_file_get_sd(-100, argv[2],
                                      OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION |
                                          DACL_SECURITY_INFORMATION,
                                      b, sizeof b, 0);
        if (n < 0) {
            perror("get descriptor");
            return 4;
        }
        for (ssize_t i = 0; i < n; i++) {
            printf("%02x", b[i]);
        }
        putchar('\n');
        return 0;
    }
    if (!strcmp(argv[1], "native-user")) {
        int fd = peios_token_open_self(0, KACS_TOKEN_QUERY);
        unsigned char b[68];
        if (fd < 0) {
            perror("open token");
            return 4;
        }
        ssize_t n = peios_token_user(fd, b, sizeof b);
        close(fd);
        if (n < 0) {
            perror("query token");
            return 4;
        }
        for (ssize_t i = 0; i < n; i++) {
            printf("%02x", b[i]);
        }
        putchar('\n');
        return 0;
    }
    if (!strcmp(argv[1], "sid")) {
        unsigned char b[68];
        char text[256];
        ssize_t n = peios_sid_parse_string(b, sizeof b, argv[2]);
        if (n < 0) {
            printf("error %d\n", errno);
            return 0;
        }
        if (peios_sid_format(b, n, text, sizeof text) < 0) return 4;
        for (ssize_t i = 0; i < n; i++) printf("%02x", b[i]);
        printf("\n%s\n", text);
        return 0;
    }
    ssize_t n;
    int condition = !strcmp(argv[1], "condition");
    if (!condition && strcmp(argv[1], "sddl")) return 2;
    n = condition ? peios_sddl_parse_condition(NULL, 0, argv[2])
                  : peios_sddl_parse_sd(NULL, 0, argv[2]);
    if (n < 0) {
        printf("error %d\n", errno);
        return 0;
    }
    unsigned char *b = malloc(n ? (size_t)n : 1);
    if (!b) return 3;
    ssize_t got =
        condition ? peios_sddl_parse_condition(b, n, argv[2]) : peios_sddl_parse_sd(b, n, argv[2]);
    if (got != n) return 4;
    for (ssize_t i = 0; i < n; i++) printf("%02x", b[i]);
    putchar('\n');
    ssize_t len = condition ? peios_sddl_format_condition(NULL, 0, b, n)
                            : peios_sddl_format_sd(NULL, 0, b, n);
    if (len < 0) {
        printf("format-error %d\n", errno);
        free(b);
        return 0;
    }
    char *s = calloc((size_t)len + 1, 1);
    if (!s) return 3;
    got = condition ? peios_sddl_format_condition(s, len + 1, b, n)
                    : peios_sddl_format_sd(s, len + 1, b, n);
    if (got != len) return 4;
    puts(s);
    free(s);
    free(b);
    return 0;
}
