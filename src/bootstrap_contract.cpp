// Evernode bootstrap contract used by Sashimono as the default contract of new HotPocket instances.
// This contract's purpose is to accept the user-defined contract bundle as a user input and replace
// itself with the supplied contract bundle. Only the user public key supplied as a cli argument will
// be allowed to submit the contract bundle.

#include "bootstrap_contract.hpp"

// This script will be renamed by this contract as post_exec.sh which HotPocket considers as
// post-execution script to be run after the contract execution completes.
constexpr const char *SCRIPT_NAME = "bootstrap_upgrade.sh";

// Filename of the contract bundle archive supplied by the user.
constexpr const char *BUNDLE_NAME = "bundle.zip";

constexpr const char *RESULT_OK = "ok";
constexpr const char *RESULT_FAIL = "fail";

constexpr const char *UPLOAD_RES = "uploadResult";
constexpr const char *STATUS_RES = "statusResult";
constexpr const char *UNKNOWN_RES = "unknownResult";

constexpr const char *UPLOAD_INPUT = "upload";
constexpr const char *STATUS_INPUT = "status";

constexpr const char *POST_EXEC_ERR_FILE = "post_exec.err";

#define HP_DEINIT                    \
    {                                \
        hp_deinit_user_input_mmap(); \
        hp_deinit_contract();        \
    }

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        std::cerr << "Owner pubkey not given.\n";
        return -1;
    }

    if (hp_init_contract() == -1)
        return 1;

    const struct hp_contract_context *ctx = hp_get_context();

    // Read and process all user inputs from the mmap.
    const void *input_mmap = hp_init_user_input_mmap();

    // Read post exec errors if any.
    jsoncons::ojson post_exec_err;
    const int error_log_res = read_post_exec_err_log(post_exec_err);

    // Clear the post exec log file once read.
    if (error_log_res >= 0)
        clear_post_exec_err_log();

    // Iterate through all users.
    for (size_t u = 0; u < ctx->users.count; u++)
    {
        const struct hp_user *user = &ctx->users.list[u];

        // If there are post exec errors for this user, Send them to the user and clear the logs.
        if (error_log_res >= 0 && post_exec_err.contains(user->public_key.data))
        {
            std::string_view error = post_exec_err[user->public_key.data].as_string_view();
            post_exec_err.erase(user->public_key.data);
            if (error.length() > 0)
                send_response_message(user, UPLOAD_RES, RESULT_FAIL, error);
        }

        // Iterate through all inputs from this user.
        for (size_t i = 0; i < user->inputs.count; i++)
        {
            const struct hp_user_input input = user->inputs.list[i];

            // Instead of mmap, we can also read the inputs from 'ctx->users.in_fd' using file I/O.
            // However, using mmap is recommended because user inputs already reside in memory.
            const void *buf = (uint8_t *)input_mmap + input.offset;
            std::string_view buffer((char *)buf, input.size);

            const jsoncons::ojson d = jsoncons::bson::decode_bson<jsoncons::ojson>(buffer);
            const std::string type = d["type"].as_string();

            // We allow only the owner public key of the instance to upload the bundle.zip
            // (Owner public key supplied as cli arg must be a 'ed'-prefixed hex encoded ed22519 public key)
            if (strcmp(user->public_key.data, argv[1]) != 0)
            {
                std::cerr << "User not allowed.\n";
                send_response_message(user, (type == UPLOAD_INPUT ? UPLOAD_RES : (type == STATUS_INPUT ? STATUS_RES : UNKNOWN_RES)), RESULT_FAIL, "UserNotAllowed");
                HP_DEINIT;
                return -1;
            }

            try
            {
                if (type == UPLOAD_INPUT)
                {
                    const jsoncons::byte_string_view data = d["content"].as_byte_string_view();

                    const int archive_fd = open(BUNDLE_NAME, O_CREAT | O_TRUNC | O_RDWR, 0644);
                    if (archive_fd == -1 || write(archive_fd, data.begin(), data.size()) == -1)
                    {
                        std::cerr << errno << ": Error saving given file.\n";
                        close(archive_fd);
                        send_response_message(user, UPLOAD_RES, RESULT_FAIL, "BundleFailed");
                        HP_DEINIT;
                        return -1;
                    }
                    close(archive_fd);

                    // Rename bootstrap_upgrade.sh to post_exec.sh and grant 'execute' permission.
                    rename(SCRIPT_NAME, HP_POST_EXEC_SCRIPT_NAME);
                    const mode_t permission_mode = 0777;
                    if (chmod(HP_POST_EXEC_SCRIPT_NAME, permission_mode) < 0)
                    {
                        std::cerr << errno << ": Chmod failed for " << HP_POST_EXEC_SCRIPT_NAME << std::endl;
                        send_response_message(user, UPLOAD_RES, RESULT_FAIL, "ScriptFailed");
                        HP_DEINIT;
                        return -1;
                    }

                    // Emit success response to the user.
                    send_response_message(user, UPLOAD_RES, RESULT_OK, "UploadSuccess");

                    // Create error log file to write errors on post exec execution.
                    post_exec_err.insert_or_assign(user->public_key.data, "");
                    write_post_exec_err_log(post_exec_err);

                    // We have found our contract package input. No need to iterate further.
                    break;
                }
                else if (type == STATUS_INPUT)
                {
                    send_response_message(user, STATUS_RES, RESULT_OK, "Bootstrap contract is online");
                }
                else
                {
                    std::cerr << "Invalid message type" << std::endl;
                    send_response_message(user, UNKNOWN_RES, RESULT_FAIL, "InvalidMessageType");
                    HP_DEINIT;
                    return -1;
                }
            }
            catch (const std::exception &e)
            {
                std::cerr << e.what() << '\n';
                send_response_message(user, (type == UPLOAD_INPUT ? UPLOAD_RES : (type == STATUS_INPUT ? STATUS_RES : UNKNOWN_RES)), RESULT_FAIL, "InternalError");
                HP_DEINIT;
                return -1;
            }
        }
    }

    post_exec_err.clear();

    HP_DEINIT;
    return 0;
}

int write_post_exec_err_log(const jsoncons::ojson &err_log)
{
    std::string json;
    jsoncons::json_options options;
    options.object_array_line_splits(jsoncons::line_split_kind::multi_line);
    options.spaces_around_comma(jsoncons::spaces_option::no_spaces);
    std::ostringstream os;
    os << jsoncons::pretty_print(err_log, options);
    json = os.str();
    os.clear();

    const int fd = open(POST_EXEC_ERR_FILE, O_CREAT | O_RDWR | O_TRUNC, 0644);
    if (fd == -1 || write(fd, json.data(), json.size()) == -1)
    {
        if (fd != -1)
            close(fd);
        return -1;
    }

    close(fd);
    return 0;
}

int read_post_exec_err_log(jsoncons::ojson &err_log)
{
    const int fd = open(POST_EXEC_ERR_FILE, O_RDONLY);
    struct stat st;
    if (fstat(fd, &st) == -1)
        return -1;

    std::string buf;
    buf.resize(st.st_size);
    if (fd == -1 || read(fd, buf.data(), buf.size()) == -1)
    {
        if (fd != -1)
            close(fd);
        return -1;
    }
    err_log = jsoncons::ojson::parse(buf, jsoncons::strict_json_parsing());

    buf.clear();
    close(fd);
    return 0;
}

int clear_post_exec_err_log()
{
    const int fd = open(POST_EXEC_ERR_FILE, O_RDONLY);
    struct stat st;
    if (fstat(fd, &st) == -1)
        return 0;
    close(fd);
    std::remove(POST_EXEC_ERR_FILE);
    return 0;
}

void send_response_message(const struct hp_user *user, std::string_view type, std::string_view status, std::string_view message)
{
    std::vector<uint8_t> msg;
    create_response_message(msg, type, status, message);
    hp_write_user_msg(user, msg.data(), msg.size());
}

void create_response_message(std::vector<uint8_t> &msg, std::string_view type, std::string_view status, std::string_view message)
{
    jsoncons::bson::bson_bytes_encoder encoder(msg);
    encoder.begin_object();
    encoder.key("type");
    encoder.string_value(type);
    encoder.key("status");
    encoder.string_value(status);
    encoder.key("message");
    encoder.string_value(message);
    encoder.end_object();
    encoder.flush();
}
