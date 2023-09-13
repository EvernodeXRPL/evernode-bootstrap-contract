#ifndef __HOTPOCKET_CONTRACT_LIB_C__
#define __HOTPOCKET_CONTRACT_LIB_C__

// Hot Pocket contract library version 0.5.0

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <poll.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include "json.h"
#include <fcntl.h>

// Private constants.
#define __HP_MMAP_BLOCK_SIZE 4096
#define __HP_MMAP_BLOCK_ALIGN(x) (((x) + ((off_t)(__HP_MMAP_BLOCK_SIZE)-1)) & ~((off_t)(__HP_MMAP_BLOCK_SIZE)-1))
#define __HP_STREAM_MSG_HEADER_SIZE 4
#define __HP_SEQPKT_MAX_SIZE 131072 // 128KB to support SEQ_PACKET sockets.
const char *__HP_PATCH_FILE_PATH = "../patch.cfg";

// Public constants.
#define HP_NPL_MSG_MAX_SIZE __HP_SEQPKT_MAX_SIZE
#define HP_PUBLIC_KEY_SIZE 66   // Hex public_key size. (64 char key + 2 chars for key type prefix)
#define HP_PRIVATE_KEY_SIZE 130 // Hex public_key size. (128 char key + 2 chars for key type prefix)
#define HP_HASH_SIZE 64         // Hex hash size.
#define HP_CONTRACT_ID_SIZE 36  // Contract Id UUIDv4 string length.
const char *HP_POST_EXEC_SCRIPT_NAME = "post_exec.sh";

#define __HP_ASSIGN_STRING(dest, elem)                                                        \
    {                                                                                         \
        if (elem->value->type == json_type_string)                                            \
        {                                                                                     \
            const struct json_string_s *value = (struct json_string_s *)elem->value->payload; \
            memcpy(dest, value->string, sizeof(dest));                                        \
        }                                                                                     \
    }

#define __HP_ASSIGN_CHAR_PTR(dest, elem)                                                      \
    {                                                                                         \
        if (elem->value->type == json_type_string)                                            \
        {                                                                                     \
            const struct json_string_s *value = (struct json_string_s *)elem->value->payload; \
            dest = (char *)malloc(value->string_size + 1);                                    \
            memcpy(dest, value->string, value->string_size + 1);                              \
        }                                                                                     \
    }

#define __HP_ASSIGN_UINT64(dest, elem)                                                        \
    {                                                                                         \
        if (elem->value->type == json_type_number)                                            \
        {                                                                                     \
            const struct json_number_s *value = (struct json_number_s *)elem->value->payload; \
            dest = strtoull(value->number, NULL, 0);                                          \
        }                                                                                     \
    }

#define __HP_ASSIGN_INT(dest, elem)                                                           \
    {                                                                                         \
        if (elem->value->type == json_type_number)                                            \
        {                                                                                     \
            const struct json_number_s *value = (struct json_number_s *)elem->value->payload; \
            dest = atoi(value->number);                                                       \
        }                                                                                     \
    }

#define __HP_ASSIGN_BOOL(dest, elem)                   \
    {                                                  \
        if (elem->value->type == json_type_true)       \
            dest = true;                               \
        else if (elem->value->type == json_type_false) \
            dest = false;                              \
    }

#define __HP_FROM_BE(buf, pos) \
    ((uint8_t)buf[pos + 0] << 24 | (uint8_t)buf[pos + 1] << 16 | (uint8_t)buf[pos + 2] << 8 | (uint8_t)buf[pos + 3])

#define __HP_TO_BE(num, buf, pos) \
    {                             \
        buf[pos] = num >> 24;     \
        buf[1 + pos] = num >> 16; \
        buf[2 + pos] = num >> 8;  \
        buf[3 + pos] = num;       \
    }

#define __HP_FREE(ptr) \
    {                  \
        free(ptr);     \
        ptr = NULL;    \
    }

#define __HP_UPDATE_CONFIG_ERROR(msg) \
    {                                 \
        fprintf(stderr, "%s\n", msg); \
        return -1;                    \
    }

enum MODE
{
    PUBLIC,
    PRIVATE
};

struct hp_user_input
{
    off_t offset;
    uint32_t size;
};

struct hp_user_inputs_collection
{
    struct hp_user_input *list;
    size_t count;
};

struct hp_public_key
{
    char data[HP_PUBLIC_KEY_SIZE + 1]; // +1 for null char.
};

struct hp_private_key
{
    char data[HP_PRIVATE_KEY_SIZE + 1]; // +1 for null char.
};

// Represents a user that is connected to HP cluster.
struct hp_user
{
    struct hp_public_key public_key;
    int outfd;
    struct hp_user_inputs_collection inputs;
};

// Represents a node that's part of unl.
struct hp_unl_node
{
    struct hp_public_key public_key;
    uint64_t active_on;
};

struct hp_users_collection
{
    struct hp_user *list;
    size_t count;
    int in_fd;
};

struct hp_public_key_collection
{
    struct hp_public_key *list;
    size_t count;
};

struct hp_unl_collection
{
    struct hp_unl_node *list;
    size_t count;
    int npl_fd;
};

struct map_entry
{
    char *key;
    char *val;
};

struct map
{
    struct map_entry *entries;
    size_t entry_count;
};

struct hp_round_limits_config
{
    size_t user_input_bytes;
    size_t user_output_bytes;
    size_t npl_output_bytes;
    size_t proc_cpu_seconds;
    size_t proc_mem_bytes;
    size_t proc_ofd_count;
    size_t exec_timeout;
};

struct consensus_config
{
    enum MODE mode;
    uint32_t roundtime;
    uint32_t stage_slice;
    uint16_t threshold;
};

struct npl_config
{
    enum MODE mode;
};

struct hp_config
{
    char *version;
    struct hp_public_key_collection unl;
    char *bin_path;
    char *bin_args;
    struct map *environment;
    uint32_t roundtime;
    uint32_t stage_slice;
    struct consensus_config consensus;
    struct npl_config npl;
    uint16_t max_input_ledger_offset;
    struct hp_round_limits_config round_limits;
};

struct hp_contract_context
{
    bool readonly;
    uint64_t timestamp;
    char contract_id[HP_CONTRACT_ID_SIZE + 1]; // +1 for null char.
    struct hp_public_key public_key;
    struct hp_private_key private_key;
    uint64_t lcl_seq_no;             // lcl sequence no.
    char lcl_hash[HP_HASH_SIZE + 1]; // +1 for null char.
    struct hp_users_collection users;
    struct hp_unl_collection unl;
};

struct __hp_contract
{
    struct hp_contract_context *cctx;
    int control_fd;
    void *user_inmap;
    size_t user_inmap_size;
};

int hp_init_contract();
int hp_deinit_contract();
const struct hp_contract_context *hp_get_context();
const void *hp_init_user_input_mmap();
void hp_deinit_user_input_mmap();
int hp_write_user_msg(const struct hp_user *user, const void *buf, const uint32_t len);
int hp_writev_user_msg(const struct hp_user *user, const struct iovec *bufs, const int buf_count);
int hp_write_npl_msg(const void *buf, const uint32_t len);
int hp_writev_npl_msg(const struct iovec *bufs, const int buf_count);
int hp_read_npl_msg(void *msg_buf, char *public_key_buf, const int timeout);
struct hp_config *hp_get_config();
int hp_update_config(const struct hp_config *config);
int hp_update_peers(const char *add_peers[], const size_t add_peers_count, const char *remove_peers[], const size_t remove_peers_count);
void hp_set_config_string(char **config_str, const char *value, const size_t value_size);
void hp_set_config_unl(struct hp_config *config, const struct hp_public_key *new_unl, const size_t new_unl_count);
void hp_free_config(struct hp_config *config);

void __hp_parse_args_json(const struct json_object_s *object);
int __hp_write_control_msg(const void *buf, const uint32_t len);
void __hp_populate_patch_from_json_object(struct hp_config *config, const struct json_object_s *object);
int __hp_write_to_patch_file(const int fd, const struct hp_config *config);
struct hp_config *__hp_read_from_patch_file(const int fd);
size_t __hp_get_json_string_array_encoded_len(const char *elems[], const size_t count);
int __hp_encode_json_string_array(char *buf, const char *elems[], const size_t count);

static struct __hp_contract __hpc = {};

int hp_init_contract()
{
    if (__hpc.cctx)
        return -1; // Already initialized.

    // Check whether we are running from terminal and produce warning.
    if (isatty(STDIN_FILENO) == 1)
    {
        fprintf(stderr, "Error: Hot Pocket smart contracts must be executed via Hot Pocket.\n");
        return -1;
    }

    char buf[4096];
    const ssize_t len = read(STDIN_FILENO, buf, sizeof(buf));
    if (len == -1)
    {
        perror("Error when reading stdin.");
        return -1;
    }

    struct json_value_s *root = json_parse(buf, len);

    if (root && root->type == json_type_object)
    {
        struct json_object_s *object = (struct json_object_s *)root->payload;
        if (object->length > 0)
        {
            // Create and populate hotpocket context.
            __hpc.cctx = (struct hp_contract_context *)malloc(sizeof(struct hp_contract_context));
            __hp_parse_args_json(object);
            __HP_FREE(root);

            return 0;
        }
    }
    __HP_FREE(root);
    return -1;
}

int hp_deinit_contract()
{
    struct hp_contract_context *cctx = __hpc.cctx;

    if (!cctx)
        return -1; // Not initialized.

    // Cleanup user input mmap (if mapped).
    hp_deinit_user_input_mmap();

    // Cleanup user and npl fd.
    close(cctx->users.in_fd);
    for (size_t i = 0; i < cctx->users.count; i++)
        close(cctx->users.list[i].outfd);
    close(cctx->unl.npl_fd);

    // Cleanup user list allocation.
    if (cctx->users.list)
    {
        for (size_t i = 0; i < cctx->users.count; i++)
            __HP_FREE(cctx->users.list[i].inputs.list);

        __HP_FREE(cctx->users.list);
    }
    // Cleanup unl list allocation.
    __HP_FREE(cctx->unl.list);
    // Cleanup contract context.
    __HP_FREE(cctx);

    close(__hpc.control_fd);
    return 0;
}

const struct hp_contract_context *hp_get_context()
{
    return __hpc.cctx;
}

const void *hp_init_user_input_mmap()
{
    if (__hpc.user_inmap)
        return __hpc.user_inmap;

    struct hp_contract_context *cctx = __hpc.cctx;
    struct stat st;
    if (fstat(cctx->users.in_fd, &st) == -1)
    {
        perror("Error in user input fd stat");
        return NULL;
    }

    if (st.st_size == 0)
        return NULL;

    const size_t mmap_size = __HP_MMAP_BLOCK_ALIGN(st.st_size);
    void *mmap_ptr = mmap(NULL, mmap_size, PROT_READ, MAP_PRIVATE, cctx->users.in_fd, 0);
    if (mmap_ptr == MAP_FAILED)
    {
        perror("Error in user input fd mmap");
        return NULL;
    }

    __hpc.user_inmap = mmap_ptr;
    __hpc.user_inmap_size = mmap_size;
    return __hpc.user_inmap;
}

void hp_deinit_user_input_mmap()
{
    if (__hpc.user_inmap)
        munmap(__hpc.user_inmap, __hpc.user_inmap_size);
    __hpc.user_inmap = NULL;
    __hpc.user_inmap_size = 0;
}

int hp_write_user_msg(const struct hp_user *user, const void *buf, const uint32_t len)
{
    const struct iovec vec = {(void *)buf, len};
    return hp_writev_user_msg(user, &vec, 1);
}

int hp_writev_user_msg(const struct hp_user *user, const struct iovec *bufs, const int buf_count)
{
    const int total_buf_count = buf_count + 1;
    struct iovec all_bufs[total_buf_count]; // We need to prepend the length header buf to indicate user message length.

    uint32_t msg_len = 0;
    for (int i = 0; i < buf_count; i++)
    {
        all_bufs[i + 1].iov_base = bufs[i].iov_base;
        all_bufs[i + 1].iov_len = bufs[i].iov_len;
        msg_len += bufs[i].iov_len;
    }

    uint8_t header_buf[__HP_STREAM_MSG_HEADER_SIZE];
    __HP_TO_BE(msg_len, header_buf, 0);

    all_bufs[0].iov_base = header_buf;
    all_bufs[0].iov_len = __HP_STREAM_MSG_HEADER_SIZE;

    return writev(user->outfd, all_bufs, total_buf_count);
}

int hp_write_npl_msg(const void *buf, const uint32_t len)
{
    if (len > HP_NPL_MSG_MAX_SIZE)
    {
        fprintf(stderr, "NPL message exceeds max length %d.\n", HP_NPL_MSG_MAX_SIZE);
        return -1;
    }

    return write(__hpc.cctx->unl.npl_fd, buf, len);
}

int hp_writev_npl_msg(const struct iovec *bufs, const int buf_count)
{
    uint32_t len = 0;
    for (int i = 0; i < buf_count; i++)
        len += bufs[i].iov_len;

    if (len > HP_NPL_MSG_MAX_SIZE)
    {
        fprintf(stderr, "NPL message exceeds max length %d.\n", HP_NPL_MSG_MAX_SIZE);
        return -1;
    }

    return writev(__hpc.cctx->unl.npl_fd, bufs, buf_count);
}

/**
 * Reads a NPL message while waiting for 'timeout' milliseconds.
 * @param msg_buf The buffer to place the incoming message. Must be of at least 'HP_NPL_MSG_MAX_SIZE' length.
 * @param public_key_buf The buffer to place the sender public_key (hex). Must be of at least 'HP_PUBLIC_KEY_SIZE' length.
 * @param timeout Maximum milliseoncds to wait until a message arrives. If 0, returns immediately.
 *                If -1, waits forever until message arrives.
 * @return Message length on success. 0 if no message arrived within timeout. -1 on error.
 */
int hp_read_npl_msg(void *msg_buf, char *public_key_buf, const int timeout)
{
    struct pollfd pfd = {__hpc.cctx->unl.npl_fd, POLLIN, 0};

    // NPL messages consist of alternating SEQ packets of public_key and data.
    // So we need to wait for both public_key and data packets to form a complete NPL message.

    // Wait for the public_key.
    if (poll(&pfd, 1, timeout) == -1)
    {
        perror("NPL channel public_key poll error");
        return -1;
    }
    else if (pfd.revents & (POLLHUP | POLLERR | POLLNVAL))
    {
        fprintf(stderr, "NPL channel public_key poll returned error: %d\n", pfd.revents);
        return -1;
    }
    else if (pfd.revents & POLLIN)
    {
        // Read public_key.
        if (read(pfd.fd, public_key_buf, HP_PUBLIC_KEY_SIZE) == -1)
        {
            perror("Error reading public_key from NPL channel");
            return -1;
        }

        // Wait for data. (data should be available immediately because we have received the public_key)
        pfd.revents = 0;
        if (poll(&pfd, 1, 100) == -1)
        {
            perror("NPL channel data poll error");
            return -1;
        }
        else if (pfd.revents & (POLLHUP | POLLERR | POLLNVAL))
        {
            fprintf(stderr, "NPL channel data poll returned error: %d\n", pfd.revents);
            return -1;
        }
        else if (pfd.revents & POLLIN)
        {
            // Read data.
            const int readres = read(pfd.fd, msg_buf, HP_NPL_MSG_MAX_SIZE);
            if (readres == -1)
            {
                perror("Error reading public_key from NPL channel");
                return -1;
            }
            return readres;
        }
    }

    return 0;
}

/**
 * Get the existing config file values.
 * @return returns a pointer to a config structure, returns NULL on error.
 */
struct hp_config *hp_get_config()
{
    const int fd = open(__HP_PATCH_FILE_PATH, O_RDONLY);
    if (fd == -1)
    {
        fprintf(stderr, "Error opening patch.cfg file.\n");
        return NULL;
    }

    struct hp_config *config = __hp_read_from_patch_file(fd);
    if (config == NULL)
        fprintf(stderr, "Error reading patch.cfg file.\n");

    close(fd);
    return config;
}

/**
 * Update the params of the existing config file.
 * @param config Pointer to the updated config struct.
 */
int hp_update_config(const struct hp_config *config)
{
    struct hp_contract_context *cctx = __hpc.cctx;

    if (cctx->readonly)
    {
        fprintf(stderr, "Config update not allowed in readonly mode.\n");
        return -1;
    }

    // Validate fields.

    if (!config->version || strlen(config->version) == 0)
        __HP_UPDATE_CONFIG_ERROR("Version cannot be empty.");

    if (config->unl.count)
    {
        for (size_t i = 0; i < config->unl.count; i++)
        {
            const char *public_key = config->unl.list[i].data;
            const size_t public_key_len = strlen(public_key);
            if (public_key_len == 0)
                __HP_UPDATE_CONFIG_ERROR("Unl public_key cannot be empty.");

            if (public_key_len != HP_PUBLIC_KEY_SIZE)
                __HP_UPDATE_CONFIG_ERROR("Unl public_key invalid. Invalid length.");

            if (public_key[0] != 'e' || public_key[1] != 'd')
                __HP_UPDATE_CONFIG_ERROR("Unl public_key invalid. Invalid format.");

            // Checking the validity of hexadecimal portion. (without 'ed').
            for (size_t j = 2; j < HP_PUBLIC_KEY_SIZE; j++)
            {
                const char current_char = public_key[j];
                if ((current_char < 'A' || current_char > 'F') && (current_char < 'a' || current_char > 'f') && (current_char < '0' || current_char > '9'))
                    __HP_UPDATE_CONFIG_ERROR("Unl public_key invalid. Invalid character.");
            }
        }
    }

    if (!config->bin_path || strlen(config->bin_path) == 0)
        __HP_UPDATE_CONFIG_ERROR("Binary path cannot be empty.");

    if (config->consensus.roundtime <= 0 || config->consensus.roundtime > 3600000)
        __HP_UPDATE_CONFIG_ERROR("Round time must be between 1 and 3600000ms inclusive.");

    if (config->consensus.stage_slice <= 0 || config->consensus.stage_slice > 33)
        __HP_UPDATE_CONFIG_ERROR("Stage slice must be between 1 and 33 percent inclusive");

    if (config->consensus.threshold <= 0 || config->consensus.threshold > 100)
        __HP_UPDATE_CONFIG_ERROR("Threshold must be between 1 and 100 percent inclusive");

    if (config->max_input_ledger_offset < 0)
        __HP_UPDATE_CONFIG_ERROR("Invalid max input ledger offset.");

    if (config->consensus.mode != PUBLIC && config->consensus.mode != PRIVATE)
        __HP_UPDATE_CONFIG_ERROR("Invalid consensus mode. Valid values: public|private");

    if (config->npl.mode != PRIVATE && config->npl.mode != PUBLIC)
        __HP_UPDATE_CONFIG_ERROR("Invalid npl mode. Valid values: public|private");

    if (config->round_limits.user_input_bytes < 0 || config->round_limits.user_output_bytes < 0 || config->round_limits.npl_output_bytes < 0 ||
        config->round_limits.proc_cpu_seconds < 0 || config->round_limits.proc_mem_bytes < 0 || config->round_limits.proc_ofd_count < 0 ||
        config->round_limits.exec_timeout < 0)
        __HP_UPDATE_CONFIG_ERROR("Invalid round limits.");

    const int fd = open(__HP_PATCH_FILE_PATH, O_RDWR);
    if (fd == -1)
        __HP_UPDATE_CONFIG_ERROR("Error opening patch.cfg file.");

    if (__hp_write_to_patch_file(fd, config) == -1)
    {
        close(fd);
        __HP_UPDATE_CONFIG_ERROR("Error writing updated config to patch.cfg file.");
    }

    close(fd);
    return 0;
}

/**
 * Assigns the given string value to the specified config string field.
 * @param config_str Pointer to the string field to populate the new value to.
 * @param value New string value.
 * @param value_size String length of the new value.
 */
void hp_set_config_string(char **config_str, const char *value, const size_t value_size)
{
    *config_str = (char *)realloc(*config_str, value_size);
    strncpy(*config_str, value, value_size);
}

/**
 * Populates the config unl list with the specified values.
 * @param config The config struct to populate the unl to.
 * @param new_unl Pointer to array of unl public_keys.
 * @param new_unl_count No. of entries in the new unl public_key array.
 */
void hp_set_config_unl(struct hp_config *config, const struct hp_public_key *new_unl, const size_t new_unl_count)
{
    const size_t mem_size = sizeof(struct hp_public_key) * new_unl_count;
    config->unl.list = (struct hp_public_key *)realloc(config->unl.list, mem_size);
    memcpy(config->unl.list, new_unl, mem_size);
    config->unl.count = new_unl_count;
}

/**
 * Frees the memory allocated for the config structure.
 * @param config Pointer to the config to be freed.
 */
void hp_free_config(struct hp_config *config)
{
    __HP_FREE(config->version);
    __HP_FREE(config->unl.list);
    __HP_FREE(config->bin_path);
    __HP_FREE(config->bin_args);
    __HP_FREE(config->environment);
    __HP_FREE(config);
}

/**
 * Updates the known-peers this node must attempt connections to.
 * @param add_peers Array of strings containing peers to be added. Each string must be in the format of "<ip>:<port>".
 * @param add_peers_count No. of peers to be added.
 * @param remove_peers Array of strings containing peers to be removed. Each string must be in the format of "<ip>:<port>".
 * @param remove_peers_count No. of peers to be removed.
 */
int hp_update_peers(const char *add_peers[], const size_t add_peers_count, const char *remove_peers[], const size_t remove_peers_count)
{
    const size_t add_json_len = __hp_get_json_string_array_encoded_len(add_peers, add_peers_count);
    char add_json[add_json_len];
    if (__hp_encode_json_string_array(add_json, add_peers, add_peers_count) == -1)
    {
        fprintf(stderr, "Error when encoding peer update changeset 'add'.\n");
        return -1;
    }

    const size_t remove_json_len = __hp_get_json_string_array_encoded_len(remove_peers, remove_peers_count);
    char remove_json[remove_json_len];
    if (__hp_encode_json_string_array(remove_json, remove_peers, remove_peers_count) == -1)
    {
        fprintf(stderr, "Error when encoding peer update changeset 'remove'.\n");
        return -1;
    }

    const size_t msg_len = 47 + (add_json_len - 1) + (remove_json_len - 1);
    char msg[msg_len];
    sprintf(msg, "{\"type\":\"peer_changeset\",\"add\":[%s],\"remove\":[%s]}", add_json, remove_json);

    if (__hp_write_control_msg(msg, msg_len - 1) == -1)
        return -1;

    return 0;
}

/**
 * Returns the null-terminated string length required to encode as a json string array without enclosing brackets.
 * @param elems Array of strings.
 * @param count No. of strings.
 */
size_t __hp_get_json_string_array_encoded_len(const char *elems[], const size_t count)
{
    size_t len = 1; // +1 for null terminator.
    for (size_t i = 0; i < count; i++)
    {
        len += (strlen(elems[i]) + 2); // Quoted string.
        if (i < count - 1)
            len += 1; // Comma
    }

    return len;
}

/**
 * Formats a string array in JSON notation without enclosing brackets.
 * @param buf Buffer to populate the encoded output.
 * @param elems Array of strings.
 * @param count No. of strings.
 */
int __hp_encode_json_string_array(char *buf, const char *elems[], const size_t count)
{
    size_t pos = 0;
    for (size_t i = 0; i < count; i++)
    {
        const char *elem = elems[i];
        buf[pos++] = '\"';
        strcpy((buf + pos), elem);
        pos += strlen(elem);
        buf[pos++] = '\"';

        if (i < count - 1)
            buf[pos++] = ',';
    }
    buf[pos] = '\0';
    return 0;
}

/**
 * Read the values from the existing patch file.
 * @param fd File discriptor of the patch.cfg file.
 * @return returns a pointer to a patch_config structure, returns NULL on error.
 */
struct hp_config *__hp_read_from_patch_file(const int fd)
{
    char buf[4096];
    const ssize_t len = read(fd, buf, sizeof(buf));
    if (len == -1)
        return NULL;

    struct json_value_s *root = json_parse(buf, len);
    if (root && root->type == json_type_object)
    {
        struct json_object_s *object = (struct json_object_s *)root->payload;
        // Create struct to populate json values.
        struct hp_config *config;
        // Allocate memory for the patch_config struct.
        config = (struct hp_config *)malloc(sizeof(struct hp_config));
        // malloc and populate values to the struct.
        __hp_populate_patch_from_json_object(config, object);
        __HP_FREE(root);
        return config;
    }

    __HP_FREE(root);
    return NULL;
}

/**
 * Write values of the given patch config struct to the file discriptor given.
 * @param fd File discriptor of the patch.cfg file.
 * @param config Patch config structure.
 */
int __hp_write_to_patch_file(const int fd, const struct hp_config *config)
{
    struct iovec iov_vec[7];
    // {version: + newline + 4 spaces => 21;
    const size_t version_len = 21 + strlen(config->version);
    char version_buf[version_len];
    sprintf(version_buf, "{\n    \"version\": \"%s\",\n", config->version);
    iov_vec[0].iov_base = version_buf;
    iov_vec[0].iov_len = version_len;

    const size_t unl_buf_size = 20 + (69 * config->unl.count - (config->unl.count ? 1 : 0)) + (9 * config->unl.count);
    char unl_buf[unl_buf_size];

    memcpy(unl_buf, "    \"unl\": [", 12);
    size_t pos = 12;
    for (size_t i = 0; i < config->unl.count; i++)
    {
        if (i > 0)
            unl_buf[pos++] = ',';

        memcpy(unl_buf + pos, "\n        ", 9);
        pos += 9;
        unl_buf[pos++] = '"';
        memcpy(unl_buf + pos, config->unl.list[i].data, HP_PUBLIC_KEY_SIZE);
        pos += HP_PUBLIC_KEY_SIZE;
        unl_buf[pos++] = '"';
    }

    memcpy(unl_buf + pos, "\n    ],\n", 8);
    iov_vec[1].iov_base = unl_buf;
    iov_vec[1].iov_len = unl_buf_size;

    // Top-level field values.

    const char *bin_string = "    \"bin_path\": \"%s\",\n    \"bin_args\": \"%s\",\n";
    const size_t bin_string_len = 43 + strlen(config->bin_path) + strlen(config->bin_args);
    char bin_buf[bin_string_len];
    sprintf(bin_buf, bin_string, config->bin_path, config->bin_args);
    iov_vec[2].iov_base = bin_buf;
    iov_vec[2].iov_len = bin_string_len;

    pos = 0;
    const size_t env_buf_size = 20 + (601 * config->environment->entry_count - (config->unl.count ? 1 : 0)) + (14 * config->environment->entry_count);
    char env_buf[env_buf_size];

    // Environment fields

    memcpy(env_buf, "    \"environment\": {", 20);
    struct map_entry *entry = config->environment->entries;
    for (size_t i = 0; i < config->environment->entry_count; i++)
    {
        if (i > 0)
            env_buf[pos++] = ',';

        memcpy(env_buf + pos, "\n        ", 9);
        pos += 9;
        env_buf[pos++] = '"';
        memcpy(env_buf + pos, entry->key, strlen(entry->key));
        pos += strlen(entry->key);
        memcpy(env_buf + pos, "\":\"", 3);
        pos += 3;
        memcpy(env_buf + pos, entry->val, strlen(entry->val));
        pos += strlen(entry->val);
        env_buf[pos++] = '"';
    }
    memcpy(env_buf + pos, "\n    },\n", 8);
    iov_vec[3].iov_base = unl_buf;
    iov_vec[3].iov_len = unl_buf_size;

    // Consensus fields

    const char *consensus_json = "    \"max_input_ledger_offset\": %s,\n"
                                 "    \"consensus\": {\n"
                                 "        \"mode\": %s,\n        \"roundtime\": %s,\n        \"stage_slice\": %s,\n"
                                 "        \"threshold\": %s\n    },\n";

    char max_input_ledger_offset_str[16], consensus_mode_str[10], roundtime_str[16], stage_slice_str[16], threshold_str[6];

    sprintf(max_input_ledger_offset_str, "%d", config->max_input_ledger_offset);
    sprintf(consensus_mode_str, "\"%s\"", config->consensus.mode == PUBLIC ? "public" : "private");
    sprintf(roundtime_str, "%d", config->consensus.roundtime);
    sprintf(stage_slice_str, "%d", config->consensus.stage_slice);
    sprintf(threshold_str, "%d", config->consensus.threshold);

    const size_t consensus_json_len = 146 + strlen(max_input_ledger_offset_str) + strlen(consensus_mode_str) + strlen(roundtime_str) + strlen(stage_slice_str) + strlen(threshold_str);
    char consensus_buf[consensus_json_len];
    sprintf(consensus_buf, consensus_json, max_input_ledger_offset_str, consensus_mode_str, roundtime_str, stage_slice_str, threshold_str);
    iov_vec[4].iov_base = consensus_buf;
    iov_vec[4].iov_len = consensus_json_len;

    // npl field values

    const char *npl_json = "    \"npl\": {\n"
                           "        \"mode\": %s\n    },\n";

    char npl_mode_str[10];
    sprintf(npl_mode_str, "\"%s\"", config->npl.mode == PUBLIC ? "public" : "private");
    const size_t npl_json_len = 37 + strlen(npl_mode_str);
    char npl_buf[npl_json_len];
    sprintf(npl_buf, npl_json, npl_mode_str);
    iov_vec[5].iov_base = npl_buf;
    iov_vec[5].iov_len = npl_json_len;

    // Round limits field values.

    const char *round_limits_json = "    \"round_limits\": {\n"
                                    "        \"user_input_bytes\": %s,\n        \"user_output_bytes\": %s,\n        \"npl_output_bytes\": %s,\n"
                                    "        \"proc_cpu_seconds\": %s,\n        \"proc_mem_bytes\": %s,\n        \"proc_ofd_count\": %s\n        \"exec_timeout\": %s\n    }\n}";

    char user_input_bytes_str[20], user_output_bytes_str[20], npl_output_bytes_str[20],
        proc_cpu_seconds_str[20], proc_mem_bytes_str[20], proc_ofd_count_str[20], exec_timeout_str[20];

    sprintf(user_input_bytes_str, "%" PRIu64, config->round_limits.user_input_bytes);
    sprintf(user_output_bytes_str, "%" PRIu64, config->round_limits.user_output_bytes);
    sprintf(npl_output_bytes_str, "%" PRIu64, config->round_limits.npl_output_bytes);

    sprintf(proc_cpu_seconds_str, "%" PRIu64, config->round_limits.proc_cpu_seconds);
    sprintf(proc_mem_bytes_str, "%" PRIu64, config->round_limits.proc_mem_bytes);
    sprintf(proc_ofd_count_str, "%" PRIu64, config->round_limits.proc_ofd_count);
    sprintf(exec_timeout_str, "%" PRIu64, config->round_limits.exec_timeout);

    const size_t round_limits_json_len = 230 + strlen(user_input_bytes_str) + strlen(user_output_bytes_str) + strlen(npl_output_bytes_str) +
                                         strlen(proc_cpu_seconds_str) + strlen(proc_mem_bytes_str) + strlen(proc_ofd_count_str) + strlen(exec_timeout_str);
    char round_limits_buf[round_limits_json_len];
    sprintf(round_limits_buf, round_limits_json,
            user_input_bytes_str, user_output_bytes_str, npl_output_bytes_str,
            proc_cpu_seconds_str, proc_mem_bytes_str, proc_ofd_count_str, exec_timeout_str);
    iov_vec[6].iov_base = round_limits_buf;
    iov_vec[6].iov_len = round_limits_json_len;

    if (ftruncate(fd, 0) == -1 ||         // Clear any previous content in the file.
        pwritev(fd, iov_vec, 6, 0) == -1) // Start writing from begining.
        return -1;

    return 0;
}

/**
 * Populate the given patch struct file from the json_object obtained from the existing patch.cfg file.
 * @param config Pointer to the patch config sturct to be populated.
 * @param object Pointer to the json object.
 */
void __hp_populate_patch_from_json_object(struct hp_config *config, const struct json_object_s *object)
{
    const struct json_object_element_s *elem = object->start;
    do
    {
        const struct json_string_s *k = elem->name;

        if (strcmp(k->string, "version") == 0)
        {
            __HP_ASSIGN_CHAR_PTR(config->version, elem);
        }
        else if (strcmp(k->string, "unl") == 0)
        {
            if (elem->value->type == json_type_array)
            {
                const struct json_array_s *unl_array = (struct json_array_s *)elem->value->payload;
                const size_t unl_count = unl_array->length;

                config->unl.count = unl_count;
                config->unl.list = unl_count ? (struct hp_public_key *)malloc(sizeof(struct hp_public_key) * unl_count) : NULL;

                if (unl_count > 0)
                {
                    struct json_array_element_s *unl_elem = unl_array->start;
                    for (size_t i = 0; i < unl_count; i++)
                    {
                        __HP_ASSIGN_STRING(config->unl.list[i].data, unl_elem);
                        unl_elem = unl_elem->next;
                    }
                }
            }
        }
        else if (strcmp(k->string, "bin_path") == 0)
        {
            __HP_ASSIGN_CHAR_PTR(config->bin_path, elem);
        }
        else if (strcmp(k->string, "bin_args") == 0)
        {
            __HP_ASSIGN_CHAR_PTR(config->bin_args, elem);
        }
        else if (strcmp(k->string, "environment") == 0)
        {
            if (elem->value->type == json_type_object)
            {
                const struct json_object_s *env_obj = (struct json_object_s *)elem->value->payload;
                const size_t elem_count = env_obj->length;

                config->environment->entry_count = elem_count;
                config->environment->entries = elem_count ? (struct map_entry *)malloc(sizeof(struct map_entry) * elem_count) : NULL;

                if (elem_count > 0)
                {
                    struct json_object_element_s *env_elem = env_obj->start;
                    for (size_t i = 0; i < elem_count; i++)
                    {
                        config->environment->entries[i].key = (char *)malloc(env_elem->name->string_size + 1);
                        memcpy(config->environment->entries[i].key, env_elem->name->string, env_elem->name->string_size + 1);

                        if (env_elem->value->type == json_type_string)
                        {
                            const struct json_string_s *value = (struct json_string_s *)env_elem->value->payload;
                            config->environment->entries[i].val = (char *)malloc(value->string_size + 1);
                            memcpy(config->environment->entries[i].val, value->string, value->string_size + 1);
                        }
                        env_elem = env_elem->next;
                    }
                }
            }
        }
        else if (strcmp(k->string, "max_input_ledger_offset") == 0)
        {
            const struct json_number_s *value = (struct json_number_s *)elem->value->payload;
            config->max_input_ledger_offset = strtoul(value->number, NULL, 0);
        }
        else if (strcmp(k->string, "consensus") == 0)
        {
            struct json_object_s *object = (struct json_object_s *)elem->value->payload;
            struct json_object_element_s *sub_ele = object->start;
            do
            {
                if (strcmp(sub_ele->name->string, "roundtime") == 0)
                {
                    __HP_ASSIGN_UINT64(config->consensus.roundtime, sub_ele);
                }
                else if (strcmp(sub_ele->name->string, "stage_slice") == 0)
                {
                    __HP_ASSIGN_UINT64(config->consensus.stage_slice, sub_ele);
                }
                else if (strcmp(sub_ele->name->string, "threshold") == 0)
                {
                    __HP_ASSIGN_UINT64(config->consensus.threshold, sub_ele);
                }
                else if (strcmp(sub_ele->name->string, "mode") == 0)
                {
                    if (sub_ele->value->type == json_type_string)
                    {
                        const struct json_string_s *value = (struct json_string_s *)sub_ele->value->payload;
                        config->consensus.mode = (strcmp(value->string, "public") == 0) ? PUBLIC : PRIVATE;
                    }
                }
                sub_ele = sub_ele->next;
            } while (sub_ele);
        }
        else if (strcmp(k->string, "npl") == 0)
        {
            struct json_object_s *object = (struct json_object_s *)elem->value->payload;
            struct json_object_element_s *sub_ele = object->start;
            do
            {
                if (strcmp(sub_ele->name->string, "mode") == 0)
                {
                    if (sub_ele->value->type == json_type_string)
                    {
                        const struct json_string_s *value = (struct json_string_s *)sub_ele->value->payload;
                        config->npl.mode = (strcmp(value->string, "public") == 0) ? PUBLIC : PRIVATE;
                    }
                }
                sub_ele = sub_ele->next;
            } while (sub_ele);
        }
        else if (strcmp(k->string, "round_limits") == 0)
        {
            struct json_object_s *object = (struct json_object_s *)elem->value->payload;
            struct json_object_element_s *sub_ele = object->start;
            do
            {
                if (strcmp(sub_ele->name->string, "user_input_bytes") == 0)
                {
                    __HP_ASSIGN_UINT64(config->round_limits.user_input_bytes, sub_ele);
                }
                else if (strcmp(sub_ele->name->string, "user_output_bytes") == 0)
                {
                    __HP_ASSIGN_UINT64(config->round_limits.user_output_bytes, sub_ele);
                }
                else if (strcmp(sub_ele->name->string, "npl_output_bytes") == 0)
                {
                    __HP_ASSIGN_UINT64(config->round_limits.npl_output_bytes, sub_ele);
                }
                else if (strcmp(sub_ele->name->string, "proc_cpu_seconds") == 0)
                {
                    __HP_ASSIGN_UINT64(config->round_limits.proc_cpu_seconds, sub_ele);
                }
                else if (strcmp(sub_ele->name->string, "proc_mem_bytes") == 0)
                {
                    __HP_ASSIGN_UINT64(config->round_limits.proc_mem_bytes, sub_ele);
                }
                else if (strcmp(sub_ele->name->string, "proc_ofd_count") == 0)
                {
                    __HP_ASSIGN_UINT64(config->round_limits.proc_ofd_count, sub_ele);
                }
                else if (strcmp(sub_ele->name->string, "exec_timeout") == 0)
                {
                    __HP_ASSIGN_UINT64(config->round_limits.exec_timeout, sub_ele);
                }
                sub_ele = sub_ele->next;
            } while (sub_ele);
        }

        elem = elem->next;
    } while (elem);
}

void __hp_parse_args_json(const struct json_object_s *object)
{
    const struct json_object_element_s *elem = object->start;
    struct hp_contract_context *cctx = __hpc.cctx;

    do
    {
        const struct json_string_s *k = elem->name;

        if (strcmp(k->string, "contract_id") == 0)
        {
            __HP_ASSIGN_STRING(cctx->contract_id, elem);
        }
        else if (strcmp(k->string, "public_key") == 0)
        {
            __HP_ASSIGN_STRING(cctx->public_key.data, elem);
        }
        else if (strcmp(k->string, "private_key") == 0)
        {
            __HP_ASSIGN_STRING(cctx->private_key.data, elem);
        }
        else if (strcmp(k->string, "timestamp") == 0)
        {
            __HP_ASSIGN_UINT64(cctx->timestamp, elem);
        }
        else if (strcmp(k->string, "readonly") == 0)
        {
            __HP_ASSIGN_BOOL(cctx->readonly, elem);
        }
        else if (strcmp(k->string, "lcl_seq_no") == 0)
        {
            __HP_ASSIGN_UINT64(cctx->lcl_seq_no, elem);
        }
        else if (strcmp(k->string, "lcl_hash") == 0)
        {
            __HP_ASSIGN_STRING(cctx->lcl_hash, elem);
        }
        else if (strcmp(k->string, "user_in_fd") == 0)
        {
            __HP_ASSIGN_INT(cctx->users.in_fd, elem);
        }
        else if (strcmp(k->string, "users") == 0)
        {
            if (elem->value->type == json_type_object)
            {
                const struct json_object_s *user_object = (struct json_object_s *)elem->value->payload;
                const size_t user_count = user_object->length;

                cctx->users.count = user_count;
                cctx->users.list = user_count ? (struct hp_user *)malloc(sizeof(struct hp_user) * user_count) : NULL;

                if (user_count > 0)
                {
                    struct json_object_element_s *user_elem = user_object->start;
                    for (size_t i = 0; i < user_count; i++)
                    {
                        struct hp_user *user = &cctx->users.list[i];
                        memcpy(user->public_key.data, user_elem->name->string, HP_PUBLIC_KEY_SIZE);

                        if (user_elem->value->type == json_type_array)
                        {
                            const struct json_array_s *arr = (struct json_array_s *)user_elem->value->payload;
                            struct json_array_element_s *arr_elem = arr->start;

                            // First element is the output fd.
                            __HP_ASSIGN_INT(user->outfd, arr_elem);
                            arr_elem = arr_elem->next;

                            // Subsequent elements are tupels of [offset, size] of input messages for this user.
                            user->inputs.count = arr->length - 1;
                            user->inputs.list = user->inputs.count ? (struct hp_user_input *)malloc(user->inputs.count * sizeof(struct hp_user_input)) : NULL;
                            for (size_t i = 0; i < user->inputs.count; i++)
                            {
                                if (arr_elem->value->type == json_type_array)
                                {
                                    const struct json_array_s *input_info = (struct json_array_s *)arr_elem->value->payload;
                                    if (input_info->length == 2)
                                    {
                                        __HP_ASSIGN_UINT64(user->inputs.list[i].offset, input_info->start);
                                        __HP_ASSIGN_UINT64(user->inputs.list[i].size, input_info->start->next);
                                    }
                                }
                                arr_elem = arr_elem->next;
                            }
                        }
                        user_elem = user_elem->next;
                    }
                }
            }
        }
        else if (strcmp(k->string, "npl_fd") == 0)
        {
            __HP_ASSIGN_INT(cctx->unl.npl_fd, elem);
        }
        else if (strcmp(k->string, "unl") == 0)
        {
            // unl is an object with public_keys as keys. Each key contains an object with that node statistics.
            if (elem->value->type == json_type_object)
            {
                const struct json_object_s *unl_obj = (struct json_object_s *)elem->value->payload;
                const size_t unl_count = unl_obj->length;

                cctx->unl.count = unl_count;
                cctx->unl.list = unl_count ? (struct hp_unl_node *)malloc(sizeof(struct hp_unl_node) * unl_count) : NULL;

                if (unl_count > 0)
                {
                    struct json_object_element_s *unl_elem = unl_obj->start;
                    for (size_t i = 0; i < unl_count; i++)
                    {
                        // Each element(key) is named by the public_key.
                        strncpy(cctx->unl.list[i].public_key.data, unl_elem->name->string, unl_elem->name->string_size);

                        if (unl_elem->value->type == json_type_object)
                        {
                            const struct json_object_s *stat_obj = (struct json_object_s *)unl_elem->value->payload;
                            struct json_object_element_s *stat_elem = stat_obj->start;
                            do
                            {
                                const struct json_string_s *k = stat_elem->name;
                                if (strcmp(k->string, "active_on") == 0)
                                {
                                    __HP_ASSIGN_UINT64(cctx->unl.list[i].active_on, stat_elem);
                                }
                                stat_elem = stat_elem->next;
                            } while (stat_elem);
                        }

                        unl_elem = unl_elem->next;
                    }
                }
            }
        }
        else if (strcmp(k->string, "control_fd") == 0)
        {
            __HP_ASSIGN_INT(__hpc.control_fd, elem);
        }

        elem = elem->next;
    } while (elem);
}

int __hp_write_control_msg(const void *buf, const uint32_t len)
{
    if (len > __HP_SEQPKT_MAX_SIZE)
    {
        fprintf(stderr, "Control message exceeds max length %d.\n", __HP_SEQPKT_MAX_SIZE);
        return -1;
    }

    return write(__hpc.control_fd, buf, len);
}

#endif