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

    // Iterate through all users.
    for (size_t u = 0; u < ctx->users.count; u++)
    {
        const struct hp_user *user = &ctx->users.list[u];

        // We allow only the owner public key of the instance to upload the bundle.zip
        // (Owner public key supplied as cli arg must be a 'ed'-prefixed hex encoded ed22519 public key)
        if (strcmp(user->public_key.data, argv[1]) != 0)
            continue;

        // Iterate through all inputs from this user.
        for (size_t i = 0; i < user->inputs.count; i++)
        {
            const struct hp_user_input input = user->inputs.list[i];

            // Instead of mmap, we can also read the inputs from 'ctx->users.in_fd' using file I/O.
            // However, using mmap is recommended because user inputs already reside in memory.
            const void *buf = (uint8_t *)input_mmap + input.offset;
            std::string_view buffer((char *)buf, input.size);
            try
            {
                const jsoncons::ojson d = jsoncons::bson::decode_bson<jsoncons::ojson>(buffer);
                const std::string type = d["type"].as_string();
                if (type == "upload")
                {
                    const jsoncons::byte_string_view data = d["content"].as_byte_string_view();

                    const int archive_fd = open(BUNDLE_NAME, O_CREAT | O_TRUNC | O_RDWR, 0644);
                    if (archive_fd == -1 || write(archive_fd, data.begin(), data.size()) == -1)
                    {
                        std::cerr << errno << ": Error saving given file.\n";
                        close(archive_fd);
                        HP_DEINIT;
                        return -1;
                    }
                    close(archive_fd);

                    // Emit success response to the user.
                    std::vector<uint8_t> msg;
                    create_response_message(msg, "uploadResult", "uploadSuccess");
                    hp_write_user_msg(user, msg.data(), msg.size());

                    // Rename bootstrap_upgrade.sh to post_exec.sh and grant 'execute' permission.
                    rename(SCRIPT_NAME, HP_POST_EXEC_SCRIPT_NAME);
                    const mode_t permission_mode = 0777;
                    if (chmod(HP_POST_EXEC_SCRIPT_NAME, permission_mode) < 0)
                    {
                        std::cerr << errno << ": Chmod failed for " << HP_POST_EXEC_SCRIPT_NAME << std::endl;
                        HP_DEINIT;
                        return -1;
                    }

                    // We have found our contract package input. No need to iterate furthur.
                    break;
                }
                else if (type == "status")
                {
                    std::vector<uint8_t> msg;
                    create_response_message(msg, "statusResult", "Bootstrap contract is online");
                    hp_write_user_msg(user, msg.data(), msg.size());
                }
                else
                {
                    std::cerr << "Invalid message type" << std::endl;
                    HP_DEINIT;
                    return -1;
                }
            }
            catch (const std::exception &e)
            {
                std::cerr << e.what() << '\n';
                HP_DEINIT;
                return -1;
            }
        }

        // We don't need to further itereate through user list. We have found our authenticated user to reach this place.
        break;
    }

    HP_DEINIT;
    return 0;
}

void create_response_message(std::vector<uint8_t> &msg, std::string_view type, std::string_view message)
{
    jsoncons::bson::bson_bytes_encoder encoder(msg);
    encoder.begin_object();
    encoder.key("type");
    encoder.string_value(type);
    encoder.key("status");
    encoder.string_value("ok");
    encoder.key("message");
    encoder.string_value(message);
    encoder.end_object();
    encoder.flush();
}
