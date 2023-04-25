#ifndef _SA_BOOTSTRAP_CONTRACT_
#define _SA_BOOTSTRAP_CONTRACT_

#include "hotpocket_contract.h"
#include <jsoncons/json.hpp>
#include <jsoncons_ext/bson/bson.hpp>

int write_upload_err_log(const jsoncons::ojson &log);
int read_upload_err_log(jsoncons::ojson &log);
int clear_upload_err_log();
void send_response_message(const struct hp_user *user, std::string_view type, std::string_view status, std::string_view message);
void create_response_message(std::vector<uint8_t> &msg, std::string_view type, std::string_view status, std::string_view message);

#endif
