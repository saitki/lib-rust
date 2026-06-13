/* nfs_client.h — API C de libnfs-rs (nfs-capi).
 *
 * Vincular contra nfs_client.dll.lib (dinámico) o nfs_client.lib (estático).
 * Convenciones:
 *   - NfsHandle* es opaco; obtenido con nfs_rs_mount, liberado con nfs_rs_unmount.
 *   - Las funciones int devuelven 0 = OK, -1 = error (ver nfs_rs_last_error).
 *   - stat/readdir devuelven char* JSON (liberar con nfs_rs_free_string).
 *   - nfs_rs_read devuelve un buffer (liberar con nfs_rs_free_bytes).
 */
#ifndef NFS_CLIENT_H
#define NFS_CLIENT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct NfsHandle NfsHandle;

/* Montaje */
NfsHandle *nfs_rs_mount(const char *url);
void nfs_rs_unmount(NfsHandle *h);
const char *nfs_rs_last_error(NfsHandle *h);
const char *nfs_rs_version(void);

/* Metadatos y directorios (devuelven JSON o NULL) */
char *nfs_rs_stat(NfsHandle *h, const char *path);
char *nfs_rs_readdir(NfsHandle *h, const char *path);

/* Lectura / escritura */
int nfs_rs_read(NfsHandle *h, const char *path, uint8_t **out_buf, size_t *out_len);
int nfs_rs_write(NfsHandle *h, const char *path, const uint8_t *data, size_t len);

/* Operaciones de nombres */
int nfs_rs_mkdir(NfsHandle *h, const char *path);
int nfs_rs_rmdir(NfsHandle *h, const char *path);
int nfs_rs_unlink(NfsHandle *h, const char *path);
int nfs_rs_rename(NfsHandle *h, const char *from, const char *to);
int nfs_rs_access(NfsHandle *h, const char *path); /* 1 = sí, 0 = no, -1 = error */

/* Liberación de memoria */
void nfs_rs_free_string(char *s);
void nfs_rs_free_bytes(uint8_t *buf, size_t len);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* NFS_CLIENT_H */
