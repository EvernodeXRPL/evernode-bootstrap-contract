#ifndef _SA_BOOTSTRAP_CONTRACT_
#define _SA_BOOTSTRAP_CONTRACT_

#include "hotpocket_contract.h"
#include <jsoncons/json.hpp>
#include <jsoncons_ext/bson/bson.hpp>

int write_post_exec_err_log(const jsoncons::ojson &err_log);
int read_post_exec_err_log(jsoncons::ojson &err_log);
int clear_post_exec_err_log();
int clear_extracts();
void send_response_message(const struct hp_user *user, std::string_view type, std::string_view status, std::string_view message);
void create_response_message(std::vector<uint8_t> &msg, std::string_view type, std::string_view status, std::string_view message);

#endif
