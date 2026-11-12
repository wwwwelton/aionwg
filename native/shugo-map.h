#ifndef AIONWG_SHUGO_MAP_H
#define AIONWG_SHUGO_MAP_H
#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint32_t state, local_addr, local_port, remote_addr, remote_port, pid;
} shugo_row;

static int shugo_has_pid(uint32_t pid, const uint32_t *pids, size_t count) {
    for (size_t i = 0; i < count; ++i) if (pid == pids[i]) return 1;
    return 0;
}

/* Only advertise a relay that actually exists, preserving the game's port pair. */
static unsigned shugo_map_rows(shugo_row *rows, size_t count,
                              const uint32_t *games, size_t game_count,
                              const uint32_t *mirrors, size_t mirror_count) {
    /* shortcut: TCP 13328 only; extend after observing another Shugo game port. */
    const uint32_t loopback = 0x0100007f;
    const uint32_t game_port = ((13328 & 255) << 8) | (13328 >> 8);
    unsigned mapped = 0;
    for (size_t i = 0; i < count; ++i) {
        shugo_row *game = &rows[i];
        if (game->state != 5 || game->remote_port != game_port ||
            game->local_addr == loopback ||
            !shugo_has_pid(game->pid, games, game_count)) continue;
        for (size_t j = 0; j < count; ++j) {
            const shugo_row *mirror = &rows[j];
            if (mirror->state != 5 || mirror->local_addr != loopback ||
                mirror->remote_addr != loopback ||
                !shugo_has_pid(mirror->pid, mirrors, mirror_count)) continue;
            if ((mirror->local_port == game->local_port && mirror->remote_port == game->remote_port) ||
                (mirror->remote_port == game->local_port && mirror->local_port == game->remote_port)) {
                game->local_addr = game->remote_addr = loopback;
                ++mapped;
                break;
            }
        }
    }
    return mapped;
}
#endif
